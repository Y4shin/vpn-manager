package config

import (
	"os"
	"path/filepath"
	"testing"
)

const minimalGood = `
listen_addr: ":8080"
public_url: "https://vpn.example.com"
oidc:
  issuer: "https://auth.example.com"
  client_id: "vpn-manager"
  client_secret_env: "OIDC_CLIENT_SECRET"
wireguard:
  users:
    interface: wg-users
    listen_port: 51820
    address: "10.100.0.1/16"
    endpoint: "vpn.example.com:51820"
    allowed_ips: ["192.168.1.0/24"]
  home:
    interface: wg-home
    listen_port: 51821
    address: "10.99.0.1/30"
    peer:
      public_key: "fakefakefakefakefakefakefakefakefakefakefak="
      allowed_ips: ["10.99.0.2/32", "192.168.1.0/24"]
groups:
  admins: { cidr: "10.100.10.0/24" }
default_group: admins
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Minimal(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	path := writeConfig(t, minimalGood)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("listen_addr: got %q", cfg.ListenAddr)
	}
	if cfg.OIDC.GroupsClaim != "groups" {
		t.Errorf("groups_claim default: got %q", cfg.OIDC.GroupsClaim)
	}
	if got := cfg.OIDCClientSecret(); got != "secret" {
		t.Errorf("OIDCClientSecret() = %q, want secret", got)
	}
}

func TestLoad_MissingPublicURL(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	bad := minimalGood
	bad = replaceLine(bad, `public_url: "https://vpn.example.com"`, "")
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing public_url")
	}
}

func TestLoad_MissingClientSecretEnv(t *testing.T) {
	// Intentionally do not set OIDC_CLIENT_SECRET.
	os.Unsetenv("OIDC_CLIENT_SECRET")
	path := writeConfig(t, minimalGood)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error when client secret env is empty")
	}
}

func TestLoad_BadGroupCIDR(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	bad := replaceLine(minimalGood, `admins: { cidr: "10.100.10.0/24" }`, `admins: { cidr: "not-a-cidr" }`)
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for bad cidr")
	}
}

func TestLoad_DefaultGroupMustExist(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	bad := replaceLine(minimalGood, `default_group: admins`, `default_group: ghost`)
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown default_group")
	}
}

func TestLoad_NoGroups(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	bad := replaceLine(minimalGood, `admins: { cidr: "10.100.10.0/24" }`, "")
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing groups")
	}
}

func replaceLine(src, needle, repl string) string {
	out := ""
	for _, line := range splitLines(src) {
		if trim(line) == trim(needle) {
			if repl != "" {
				out += repl + "\n"
			}
			continue
		}
		out += line + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
