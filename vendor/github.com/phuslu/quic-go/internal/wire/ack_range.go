package wire

import "github.com/phuslu/quic-go/internal/protocol"

// AckRange is an ACK range
type AckRange struct {
	FirstPacketNumber protocol.PacketNumber
	LastPacketNumber  protocol.PacketNumber
}
