package render

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
)

func TestWireguardConf_GoldenOutput(t *testing.T) {
	got, err := WireguardConf(ClientConfigInput{
		PrivateKey:      "PRIVKEY=",
		Address:         "10.100.10.2",
		DNS:             []string{"192.168.1.1"},
		ServerPublicKey: "SERVERPUB=",
		Endpoint:        "vpn.example.com:51820",
		AllowedIPs:      []string{"192.168.1.0/24"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := `[Interface]
PrivateKey = PRIVKEY=
Address = 10.100.10.2/32
DNS = 192.168.1.1

[Peer]
PublicKey = SERVERPUB=
Endpoint = vpn.example.com:51820
AllowedIPs = 192.168.1.0/24
PersistentKeepalive = 25
`
	if got != want {
		t.Errorf("conf mismatch\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

func TestWireguardConf_NoDNSOmitsLine(t *testing.T) {
	got, err := WireguardConf(ClientConfigInput{
		PrivateKey:      "K=",
		Address:         "10.0.0.2",
		ServerPublicKey: "S=",
		Endpoint:        "e:51820",
		AllowedIPs:      []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "DNS =") {
		t.Errorf("DNS line should be omitted when empty:\n%s", got)
	}
}

func TestQRDataURI_IsValidPNG(t *testing.T) {
	uri, err := QRDataURI("hello world")
	if err != nil {
		t.Fatalf("qr: %v", err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("wrong prefix: %s...", uri[:40])
	}
	raw, err := base64.StdEncoding.DecodeString(uri[len(prefix):])
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
		t.Errorf("not a valid png: %v", err)
	}
}
