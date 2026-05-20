package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	PublicURL  string `yaml:"public_url"`
	DataDir    string `yaml:"data_dir"`

	OIDC      OIDCConfig         `yaml:"oidc"`
	WireGuard WireGuardConfig    `yaml:"wireguard"`
	Groups    map[string]Group   `yaml:"groups"`
	Default   string             `yaml:"default_group"`
}

type OIDCConfig struct {
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client_id"`
	ClientSecretEnv string   `yaml:"client_secret_env"`
	GroupsClaim     string   `yaml:"groups_claim"`
	Scopes          []string `yaml:"scopes"`
}

type WireGuardConfig struct {
	Users UsersTunnel `yaml:"users"`
	Home  HomeTunnel  `yaml:"home"`
}

type UsersTunnel struct {
	Interface  string   `yaml:"interface"`
	ListenPort int      `yaml:"listen_port"`
	Address    string   `yaml:"address"`
	Endpoint   string   `yaml:"endpoint"`
	DNS        []string `yaml:"dns"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

type HomeTunnel struct {
	Interface  string   `yaml:"interface"`
	ListenPort int      `yaml:"listen_port"`
	Address    string   `yaml:"address"`
	Peer       HomePeer `yaml:"peer"`
}

type HomePeer struct {
	PublicKey  string   `yaml:"public_key"`
	AllowedIPs []string `yaml:"allowed_ips"`
}

type Group struct {
	CIDR string `yaml:"cidr"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config invalid: %w", err)
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/vpn-manager"
	}
	if c.OIDC.GroupsClaim == "" {
		c.OIDC.GroupsClaim = "groups"
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "profile", "email", "groups"}
	}
}

func (c *Config) validate() error {
	if c.PublicURL == "" {
		return fmt.Errorf("public_url is required")
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" || c.OIDC.ClientSecretEnv == "" {
		return fmt.Errorf("oidc issuer, client_id, client_secret_env are required")
	}
	if os.Getenv(c.OIDC.ClientSecretEnv) == "" {
		return fmt.Errorf("oidc client secret env %q is empty", c.OIDC.ClientSecretEnv)
	}
	if err := validateTunnel("users", c.WireGuard.Users.Interface, c.WireGuard.Users.ListenPort, c.WireGuard.Users.Address); err != nil {
		return err
	}
	if c.WireGuard.Users.Endpoint == "" {
		return fmt.Errorf("wireguard.users.endpoint is required (host:port shown to clients)")
	}
	if err := validateTunnel("home", c.WireGuard.Home.Interface, c.WireGuard.Home.ListenPort, c.WireGuard.Home.Address); err != nil {
		return err
	}
	if c.WireGuard.Home.Peer.PublicKey == "" {
		return fmt.Errorf("wireguard.home.peer.public_key is required (opnsense pubkey)")
	}
	for _, a := range c.WireGuard.Home.Peer.AllowedIPs {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return fmt.Errorf("wireguard.home.peer.allowed_ips: %q: %w", a, err)
		}
	}
	if len(c.Groups) == 0 {
		return fmt.Errorf("at least one group is required")
	}
	for name, g := range c.Groups {
		if _, _, err := net.ParseCIDR(g.CIDR); err != nil {
			return fmt.Errorf("groups.%s.cidr: %w", name, err)
		}
	}
	if c.Default != "" {
		if _, ok := c.Groups[c.Default]; !ok {
			return fmt.Errorf("default_group %q not found in groups", c.Default)
		}
	}
	return nil
}

func validateTunnel(label, iface string, port int, addr string) error {
	if iface == "" {
		return fmt.Errorf("wireguard.%s.interface is required", label)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("wireguard.%s.listen_port is invalid", label)
	}
	if _, _, err := net.ParseCIDR(addr); err != nil {
		return fmt.Errorf("wireguard.%s.address: %w", label, err)
	}
	return nil
}

func (c *Config) OIDCClientSecret() string {
	return os.Getenv(c.OIDC.ClientSecretEnv)
}
