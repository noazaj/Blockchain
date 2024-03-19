package crypto

import "crypto/ed25519"

type PrivateKey struct {
	key ed25519.PrivateKey
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(p.key, msg)
}

type PublicKey struct {
	key ed25519.PublicKey
}
