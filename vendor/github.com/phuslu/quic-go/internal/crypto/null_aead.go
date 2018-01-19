package crypto

import "github.com/phuslu/quic-go/internal/protocol"

// NewNullAEAD creates a NullAEAD
func NewNullAEAD(p protocol.Perspective, connID protocol.ConnectionID, v protocol.VersionNumber) (AEAD, error) {
	if v.UsesTLS() {
		return newNullAEADAESGCM(connID, p)
	}
	return &nullAEADFNV128a{perspective: p}, nil
}
