package ipam

import (
	"fmt"
	"net/netip"
)

type Allocator struct {
	groups map[string]netip.Prefix
}

func New(groupCIDRs map[string]string) (*Allocator, error) {
	out := make(map[string]netip.Prefix, len(groupCIDRs))
	for name, cidr := range groupCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("group %q: parse cidr: %w", name, err)
		}
		out[name] = p.Masked()
	}
	return &Allocator{groups: out}, nil
}

// Allocate returns the next free /32 in the given group's CIDR.
// Skips: network address, broadcast address, and the group's `.1` (reserved
// for whatever default gateway one might want, kept symmetric per group).
func (a *Allocator) Allocate(group string, used map[string]struct{}) (string, error) {
	prefix, ok := a.groups[group]
	if !ok {
		return "", fmt.Errorf("unknown group %q", group)
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("only IPv4 supported, got %s", prefix)
	}

	network := prefix.Addr()
	broadcast := lastAddr(prefix)
	gateway := network.Next() // .1

	for ip := gateway.Next(); ip.Compare(broadcast) < 0; ip = ip.Next() {
		if !prefix.Contains(ip) {
			break
		}
		s := ip.String()
		if _, taken := used[s]; taken {
			continue
		}
		return s, nil
	}
	return "", fmt.Errorf("no free IPs in group %q (%s)", group, prefix)
}

// GroupForUserGroups picks the first group from the user's OIDC groups that
// the deployment knows about. Falls back to `defaultGroup` if none match.
// Returns "" if no match and no default.
func (a *Allocator) GroupForUserGroups(userGroups []string, defaultGroup string) string {
	for _, g := range userGroups {
		if _, ok := a.groups[g]; ok {
			return g
		}
	}
	if defaultGroup != "" {
		if _, ok := a.groups[defaultGroup]; ok {
			return defaultGroup
		}
	}
	return ""
}

func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	if !addr.Is4() {
		return addr
	}
	bytes := addr.As4()
	hostBits := 32 - p.Bits()
	for i := 0; i < hostBits; i++ {
		byteIdx := 3 - i/8
		bitIdx := i % 8
		bytes[byteIdx] |= 1 << bitIdx
	}
	return netip.AddrFrom4(bytes)
}
