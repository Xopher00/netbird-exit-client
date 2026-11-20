package device

type EventType uint32

// NOTE: discriminants must be kept in sync with `MaybenotEventType` in maybenot-ffi/maybenot.h
const (
	NormalReceived  = EventType(0)
	PaddingReceived = EventType(1)
	TunnelReceived  = EventType(2)
	NormalSent      = EventType(3)
	PaddingSent     = EventType(4)
	TunnelSent      = EventType(5)
	BlockingBegin   = EventType(6)
	BlockingEnd     = EventType(7)
	TimerBegin      = EventType(8)
	TimerEnd        = EventType(9)
)

const (
	// Length (in bytes) of the header of a DAITA padding packet.
	DaitaHeaderLen uint16 = 4

	// The first byte of the header, taking the place of the IP version field, is the DAITA marker.
	// This is used to differentiate DAITA padding packets from IP packets.
	DaitaPaddingMarker uint8 = 0xff

	// Offset (in bytes) before the 16 bit packet length field in the DAITA header
	DaitaOffsetTotalLength uint16 = 2
)

// Daita is what the device's send and receive paths call. Padding-only machines author only SendPadding, so the
// paths send the six events from NormalReceived to TunnelSent alone; machine is set only for PaddingSent.
type Daita interface {
	Close()
	Event(peer *Peer, eventType EventType, machine uint64)
	// RecordSize notes the size of a real packet sent, so dummies take sizes the peer really sends.
	RecordSize(size int)
}
