package render

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"

	"github.com/skip2/go-qrcode"
)

type ClientConfigInput struct {
	PrivateKey      string
	Address         string // /32 the client gets
	DNS             []string
	ServerPublicKey string
	Endpoint        string
	AllowedIPs      []string
}

const clientTpl = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address }}/32
{{- if .DNS }}
DNS = {{ join .DNS ", " }}
{{- end }}

[Peer]
PublicKey = {{ .ServerPublicKey }}
Endpoint = {{ .Endpoint }}
AllowedIPs = {{ join .AllowedIPs ", " }}
PersistentKeepalive = 25
`

func WireguardConf(in ClientConfigInput) (string, error) {
	t, err := template.New("wg").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(clientTpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, in); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// QRDataURI returns the config encoded as a base64 PNG data URI suitable for
// dropping straight into an <img src=...>.
func QRDataURI(conf string) (string, error) {
	png, err := qrcode.Encode(conf, qrcode.Medium, 320)
	if err != nil {
		return "", fmt.Errorf("encode qr: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
