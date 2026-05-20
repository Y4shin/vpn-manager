package wg

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/patric/vpn-manager/internal/config"
)

type Controller struct {
	client *wgctrl.Client
	cfg    *config.Config

	usersKey wgtypes.Key
	homeKey  wgtypes.Key
}

func New(cfg *config.Config) (*Controller, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl new: %w", err)
	}
	ctrl := &Controller{client: c, cfg: cfg}

	ctrl.usersKey, err = loadOrCreateKey(filepath.Join(cfg.DataDir, "wg-users.key"))
	if err != nil {
		return nil, fmt.Errorf("users key: %w", err)
	}
	ctrl.homeKey, err = loadOrCreateKey(filepath.Join(cfg.DataDir, "wg-home.key"))
	if err != nil {
		return nil, fmt.Errorf("home key: %w", err)
	}
	return ctrl, nil
}

func (c *Controller) Close() error { return c.client.Close() }

func (c *Controller) UsersPublicKey() string { return c.usersKey.PublicKey().String() }
func (c *Controller) HomePublicKey() string  { return c.homeKey.PublicKey().String() }

// Bootstrap brings both interfaces up: creates the WG link if absent, assigns
// the address, sets the wg device config, brings the link up, and installs
// the required routes (192.168.x.x via wg-home, user supernet via wg-users).
func (c *Controller) Bootstrap() error {
	if err := c.ensureLink(c.cfg.WireGuard.Users.Interface, c.cfg.WireGuard.Users.Address); err != nil {
		return fmt.Errorf("ensure wg-users link: %w", err)
	}
	if err := c.ensureLink(c.cfg.WireGuard.Home.Interface, c.cfg.WireGuard.Home.Address); err != nil {
		return fmt.Errorf("ensure wg-home link: %w", err)
	}

	usersPort := c.cfg.WireGuard.Users.ListenPort
	if err := c.client.ConfigureDevice(c.cfg.WireGuard.Users.Interface, wgtypes.Config{
		PrivateKey:   &c.usersKey,
		ListenPort:   &usersPort,
		ReplacePeers: true,
		Peers:        nil, // populated separately by Apply()
	}); err != nil {
		return fmt.Errorf("configure wg-users: %w", err)
	}

	homePort := c.cfg.WireGuard.Home.ListenPort
	homePeerKey, err := wgtypes.ParseKey(c.cfg.WireGuard.Home.Peer.PublicKey)
	if err != nil {
		return fmt.Errorf("parse opnsense pubkey: %w", err)
	}
	homePeerNets, err := parseCIDRs(c.cfg.WireGuard.Home.Peer.AllowedIPs)
	if err != nil {
		return fmt.Errorf("parse home peer allowed_ips: %w", err)
	}
	if err := c.client.ConfigureDevice(c.cfg.WireGuard.Home.Interface, wgtypes.Config{
		PrivateKey:   &c.homeKey,
		ListenPort:   &homePort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:         homePeerKey,
			AllowedIPs:        homePeerNets,
			ReplaceAllowedIPs: true,
		}},
	}); err != nil {
		return fmt.Errorf("configure wg-home: %w", err)
	}

	for _, net := range homePeerNets {
		if err := ensureRoute(c.cfg.WireGuard.Home.Interface, net); err != nil {
			return fmt.Errorf("route %s via wg-home: %w", net, err)
		}
	}
	return nil
}

// Apply replaces the user-facing peer set on wg-users with the given list.
// Each entry maps a peer's wireguard public key to the /32 it owns.
type UserPeer struct {
	PublicKey string
	IP        string
}

func (c *Controller) Apply(peers []UserPeer) error {
	pcs := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %q: parse pubkey: %w", p.PublicKey, err)
		}
		ip := net.ParseIP(p.IP)
		if ip == nil {
			return fmt.Errorf("peer %q: parse ip %q", p.PublicKey, p.IP)
		}
		pcs = append(pcs, wgtypes.PeerConfig{
			PublicKey: key,
			AllowedIPs: []net.IPNet{{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			}},
			ReplaceAllowedIPs: true,
		})
	}
	return c.client.ConfigureDevice(c.cfg.WireGuard.Users.Interface, wgtypes.Config{
		ReplacePeers: true,
		Peers:        pcs,
	})
}

// Handshakes returns (publicKey -> last handshake) for peers on wg-users.
// Zero time means "no handshake yet".
func (c *Controller) Handshakes() (map[string]time.Time, error) {
	dev, err := c.client.Device(c.cfg.WireGuard.Users.Interface)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(dev.Peers))
	for _, p := range dev.Peers {
		out[p.PublicKey.String()] = p.LastHandshakeTime
	}
	return out, nil
}

func (c *Controller) ensureLink(name, address string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return err
		}
		la := netlink.NewLinkAttrs()
		la.Name = name
		wg := &netlink.Wireguard{LinkAttrs: la}
		if err := netlink.LinkAdd(wg); err != nil {
			return fmt.Errorf("link add: %w", err)
		}
		link, err = netlink.LinkByName(name)
		if err != nil {
			return err
		}
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}
	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	have := false
	for _, a := range existing {
		if a.Equal(*addr) {
			have = true
			break
		}
	}
	if !have {
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("addr add: %w", err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	return nil
}

func ensureRoute(iface string, dst net.IPNet) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &dst,
		Scope:     netlink.SCOPE_LINK,
	}
	// RouteReplace is idempotent.
	return netlink.RouteReplace(route)
}

func parseCIDRs(in []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(in))
	for _, s := range in {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, *n)
	}
	return out, nil
}

func loadOrCreateKey(path string) (wgtypes.Key, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return wgtypes.ParseKey(string(data))
	}
	if !os.IsNotExist(err) {
		return wgtypes.Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return wgtypes.Key{}, err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.WriteFile(path, []byte(key.String()), 0o600); err != nil {
		return wgtypes.Key{}, err
	}
	return key, nil
}
