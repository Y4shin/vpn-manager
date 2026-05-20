package wg

import "time"

// WGControl is the surface the web layer needs from the WireGuard controller.
// Defined as an interface so tests can substitute a fake without bringing up
// real kernel WG interfaces. *Controller satisfies it.
type WGControl interface {
	UsersPublicKey() string
	Apply(peers []UserPeer) error
	Handshakes() (map[string]time.Time, error)
}
