package wg

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// Keypair is a freshly-generated client keypair. Private side only lives in
// the response of one HTTP request — never persisted.
type Keypair struct {
	Private string
	Public  string
}

func NewKeypair() (Keypair, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: k.String(), Public: k.PublicKey().String()}, nil
}
