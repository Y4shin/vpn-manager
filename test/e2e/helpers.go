//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const composeFile = "docker-compose.yml"

// dc runs `docker compose -f docker-compose.yml <args...>` and returns the
// captured stdout. Failures fail the test.
func dc(t *testing.T, args ...string) string {
	t.Helper()
	out, err := dcOpt(args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func dcOpt(args ...string) (string, error) {
	full := append([]string{"compose", "-f", composeFile}, args...)
	cmd := exec.Command("docker", full...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// exec runs a command inside a compose service and returns stdout+stderr.
// Failures (non-zero exit) fail the test with the captured output.
func execIn(t *testing.T, service string, argv ...string) string {
	t.Helper()
	out, err := execInOpt(service, argv...)
	if err != nil {
		t.Fatalf("exec %s %s: %v\n%s", service, strings.Join(argv, " "), err, out)
	}
	return out
}

func execInOpt(service string, argv ...string) (string, error) {
	args := append([]string{"compose", "-f", composeFile, "exec", "-T", service}, argv...)
	cmd := exec.Command("docker", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// eventually polls fn() until it returns nil or the timeout fires.
func eventually(t *testing.T, what string, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s after %s: %v", what, timeout, lastErr)
}

func nonEmptyHandshake(t *testing.T, service, iface string) error {
	out, err := execInOpt(service, "wg", "show", iface, "latest-handshakes")
	if err != nil {
		return fmt.Errorf("wg show: %v: %s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] != "0" {
			return nil
		}
	}
	return fmt.Errorf("no peer has a non-zero handshake yet:\n%s", out)
}
