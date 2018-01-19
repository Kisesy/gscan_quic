package handshake

import (
	"crypto/tls"
	"io"

	"github.com/bifurcation/mint"
	"github.com/phuslu/quic-go/internal/crypto"
	"github.com/phuslu/quic-go/internal/protocol"
)

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// A TLSExtensionHandler sends and received the QUIC TLS extension.
// It provides the parameters sent by the peer on a channel.
type TLSExtensionHandler interface {
	Send(mint.HandshakeType, *mint.ExtensionList) error
	Receive(mint.HandshakeType, *mint.ExtensionList) error
	GetPeerParams() <-chan TransportParameters
}

// MintTLS combines some methods needed to interact with mint.
type MintTLS interface {
	crypto.TLSExporter

	// additional methods
	Handshake() mint.Alert
	State() mint.State

	SetCryptoStream(io.ReadWriter)
	SetExtensionHandler(mint.AppExtensionHandler) error
}

// CryptoSetup is a crypto setup
type CryptoSetup interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error)
	HandleCryptoStream() (*tls.ConnectionState, error)
	// TODO: clean up this interface
	DiversificationNonce() []byte   // only needed for cryptoSetupServer
	SetDiversificationNonce([]byte) // only needed for cryptoSetupClient

	GetSealer() (protocol.EncryptionLevel, Sealer)
	GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (Sealer, error)
	GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer)

	ConnectionState() *tls.ConnectionState
}
