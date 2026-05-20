//go:build e2e

package e2e

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var keep = flag.Bool("keep", false, "leave docker compose stack up after the run (for debugging)")

func TestMain(m *testing.M) {
	flag.Parse()

	// Fail fast if docker isn't available.
	if out, err := dcOpt("version"); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose unavailable: %v\n%s", err, out)
		os.Exit(2)
	}

	// Bring up the stack. --build to pick up any source changes.
	if out, err := dcOpt("up", "-d", "--build", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "compose up failed: %v\n%s", err, out)
		_, _ = dcOpt("down", "-v")
		os.Exit(2)
	}

	code := m.Run()

	if !*keep {
		_, _ = dcOpt("down", "-v")
	} else {
		fmt.Fprintln(os.Stderr, "--keep: leaving compose stack running")
	}
	os.Exit(code)
}

// 1) opnsense WG handshake established.
func TestOpnsenseHandshakeReady(t *testing.T) {
	eventually(t, "wg-home handshake from opnsense", 60*time.Second, func() error {
		return nonEmptyHandshake(t, "vps", "wg-home")
	})
}

// 2)+3) admin can log in, peer appears with admin-CIDR IP, ping reaches home-nas.
func TestAdminLoginAndPingHomeNAS(t *testing.T) {
	requireHandshake(t)

	confAndID := execIn(t, "client-admin",
		"/usr/local/bin/login-and-fetch", "--user=alice", "--create=laptop")
	conf, devID := parseLoginOutput(t, confAndID)
	if !strings.Contains(conf, "10.100.10.") {
		t.Fatalf("admin device IP should be in 10.100.10.0/24:\n%s", conf)
	}
	t.Logf("admin device id=%s", devID)

	writeAndUp(t, "client-admin", conf)
	t.Cleanup(func() { _, _ = execInOpt("client-admin", "wg-quick", "down", "wg0") })

	// Verify the peer landed on vps.
	out := execIn(t, "vps", "wg", "show", "wg-users", "peers")
	if strings.TrimSpace(out) == "" {
		t.Fatalf("expected at least one user peer on wg-users")
	}

	// Ping home-nas via the tunnel.
	pingOut := execIn(t, "client-admin", "ping", "-c", "3", "-W", "2", "192.168.1.10")
	if !strings.Contains(pingOut, "3 packets transmitted, 3 packets received") &&
		!strings.Contains(pingOut, "3 received") {
		t.Fatalf("ping to home-nas should succeed:\n%s", pingOut)
	}
}

// 4) source IP preserved across vps forwarding (no SNAT regression).
func TestSourceIPPreserved(t *testing.T) {
	requireHandshake(t)
	conf, _ := loginAndCreate(t, "client-admin", "alice", "src-ip-check")
	if !strings.Contains(conf, "10.100.10.") {
		t.Fatalf("admin IP missing from conf:\n%s", conf)
	}
	writeAndUp(t, "client-admin", conf)
	t.Cleanup(func() { _, _ = execInOpt("client-admin", "wg-quick", "down", "wg0") })

	// Start tcpdump on opnsense, then ping.
	dumpCmd := "tcpdump -i wg0 -nn -c 3 icmp 2>&1"
	type result struct {
		out string
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		o, e := execInOpt("opnsense", "sh", "-c", dumpCmd)
		resCh <- result{o, e}
	}()

	time.Sleep(500 * time.Millisecond)
	_ = execIn(t, "client-admin", "ping", "-c", "3", "-W", "2", "192.168.1.10")

	res := <-resCh
	if res.err != nil {
		t.Fatalf("tcpdump on opnsense failed: %v\n%s", res.err, res.out)
	}
	if !strings.Contains(res.out, "10.100.10.") {
		t.Errorf("expected source 10.100.10.X in tcpdump output:\n%s", res.out)
	}
	if strings.Contains(res.out, "10.99.0.1 ") {
		t.Errorf("found 10.99.0.1 (VPS link IP) as source — SNAT regression!\n%s", res.out)
	}
}

// 5) guest is blocked by opnsense firewall while admin still works.
func TestGuestBlockedByFirewall(t *testing.T) {
	requireHandshake(t)

	// Admin first — sanity baseline.
	confA, _ := loginAndCreate(t, "client-admin", "alice", "sanity-laptop")
	if !strings.Contains(confA, "10.100.10.") {
		t.Fatalf("admin conf missing 10.100.10.X")
	}
	writeAndUp(t, "client-admin", confA)
	t.Cleanup(func() { _, _ = execInOpt("client-admin", "wg-quick", "down", "wg0") })
	if _, err := execInOpt("client-admin", "ping", "-c", "2", "-W", "2", "192.168.1.10"); err != nil {
		t.Fatalf("admin should reach 192.168.1.10")
	}

	// Guest now.
	confG, _ := loginAndCreate(t, "client-guest", "bob", "phone")
	if !strings.Contains(confG, "10.100.30.") {
		t.Fatalf("guest IP should be in 10.100.30.0/24:\n%s", confG)
	}
	writeAndUp(t, "client-guest", confG)
	t.Cleanup(func() { _, _ = execInOpt("client-guest", "wg-quick", "down", "wg0") })

	// Guest can still reach 192.168.1.10 (NAS) per the rule.
	if _, err := execInOpt("client-guest", "ping", "-c", "2", "-W", "2", "192.168.1.10"); err != nil {
		t.Errorf("guest should be allowed to reach NAS 192.168.1.10: %v", err)
	}
	// But not any other home-LAN address.
	if _, err := execInOpt("client-guest", "ping", "-c", "2", "-W", "2", "192.168.1.20"); err == nil {
		t.Errorf("guest should be blocked from 192.168.1.20 by opnsense firewall")
	}
}

// 6) revoke + reconcile after restart.
func TestRevokeAndReconcile(t *testing.T) {
	requireHandshake(t)
	conf, devID := loginAndCreate(t, "client-admin", "alice", "revoke-laptop")
	ip := extractAddress(t, conf)
	writeAndUp(t, "client-admin", conf)
	t.Cleanup(func() { _, _ = execInOpt("client-admin", "wg-quick", "down", "wg0") })

	// Baseline: ping works.
	if _, err := execInOpt("client-admin", "ping", "-c", "2", "-W", "2", "192.168.1.10"); err != nil {
		t.Fatalf("baseline ping should work")
	}

	// Revoke via the UI.
	_ = execIn(t, "client-admin", "/usr/local/bin/login-and-fetch", "--user=alice", "--delete="+devID)

	// The /32 for THIS device should disappear from wg show wg-users.
	eventually(t, "specific peer removed from wg-users", 10*time.Second, func() error {
		out, _ := execInOpt("vps", "wg", "show", "wg-users", "allowed-ips")
		if strings.Contains(out, ip+"/32") {
			return fmt.Errorf("our /32 still in allowed-ips:\n%s", out)
		}
		return nil
	})

	// Ping should now fail.
	if _, err := execInOpt("client-admin", "ping", "-c", "2", "-W", "2", "192.168.1.10"); err == nil {
		t.Errorf("ping should fail after revoke")
	}

	// Bring up a fresh device, then bounce vps and confirm the reconciler restores it.
	_, _ = execInOpt("client-admin", "wg-quick", "down", "wg0")
	conf2, _ := loginAndCreate(t, "client-admin", "alice", "post-restart-laptop")
	ip2 := extractAddress(t, conf2)
	writeAndUp(t, "client-admin", conf2)

	if _, err := execInOpt("client-admin", "ping", "-c", "2", "-W", "2", "192.168.1.10"); err != nil {
		t.Fatalf("ping should work for new device")
	}

	dc(t, "restart", "vps")
	eventually(t, "vps healthy after restart", 60*time.Second, func() error {
		out, err := execInOpt("vps", "wget", "-q", "-O-", "http://localhost:8080/healthz")
		if err != nil {
			return fmt.Errorf("healthz: %v: %s", err, out)
		}
		return nil
	})
	eventually(t, "reconciler restored our /32", 60*time.Second, func() error {
		out, _ := execInOpt("vps", "wg", "show", "wg-users", "allowed-ips")
		if !strings.Contains(out, ip2+"/32") {
			return fmt.Errorf("our /32 missing:\n%s", out)
		}
		return nil
	})
	eventually(t, "wg-home handshake re-established", 60*time.Second, func() error {
		return nonEmptyHandshake(t, "vps", "wg-home")
	})
	eventually(t, "ping resumes after vps restart", 60*time.Second, func() error {
		_, err := execInOpt("client-admin", "ping", "-c", "2", "-W", "2", "192.168.1.10")
		return err
	})
}

func extractAddress(t *testing.T, conf string) string {
	t.Helper()
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Address") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSuffix(strings.TrimSpace(parts[1]), "/32")
			}
		}
	}
	t.Fatalf("conf missing Address line:\n%s", conf)
	return ""
}

// ---- helpers below ----

func requireHandshake(t *testing.T) {
	t.Helper()
	eventually(t, "wg-home handshake", 60*time.Second, func() error {
		return nonEmptyHandshake(t, "vps", "wg-home")
	})
}

func parseLoginOutput(t *testing.T, out string) (conf, id string) {
	t.Helper()
	lines := strings.SplitN(out, "\n", 2)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "DEVICE_ID=") {
		t.Fatalf("login-and-fetch output malformed:\n%s", out)
	}
	id = strings.TrimPrefix(lines[0], "DEVICE_ID=")
	conf = strings.TrimSpace(lines[1])
	return
}

func loginAndCreate(t *testing.T, container, user, name string) (conf, id string) {
	t.Helper()
	out := execIn(t, container,
		"/usr/local/bin/login-and-fetch", "--user="+user, "--create="+name)
	return parseLoginOutput(t, out)
}

func writeAndUp(t *testing.T, container, conf string) {
	t.Helper()
	// Pipe the config in via stdin to avoid quoting nightmares.
	cmd := []string{"compose", "-f", composeFile, "exec", "-T", container,
		"sh", "-c", "cat > /etc/wireguard/wg0.conf && chmod 600 /etc/wireguard/wg0.conf && wg-quick up wg0"}
	c := exec.Command("docker", cmd...)
	c.Stdin = strings.NewReader(conf)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("writeAndUp(%s) failed: %v\n%s", container, err, out)
	}
}
