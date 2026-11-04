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

type Daita interface {
	Close()
	NormalSent(peer *Peer)
	NormalReceived(peer *Peer)
	PaddingSent(peer *Peer, machine_id uint64)
	PaddingReceived(peer *Peer)
	TunnelSent(peer *Peer)
	TunnelReceived(peer *Peer)

	// Blocking (the Maybenot BlockOutgoing action): blockHolds takes a TUN batch into the hold queue
	// while a block is active (false: not blocked, or the hold is full and the batch flows through);
	// maySend reports whether padding with the bypass flag may leave during the block; holdPadding takes a built
	// padding packet into the hold; releaseHeld sends every held packet at the block's end; dropHeld
	// discards them (peer stopped or reset).
	blockHolds(elems []*QueueOutboundElement) bool
	maySend(bypass bool) bool
	holdPadding(elem *QueueOutboundElement, machine uint64) bool
	releaseHeld(peer *Peer)
	dropHeld(peer *Peer)
}

func (event EventType) String() string {
	var pretty string
	switch event {
	case NormalReceived:
		pretty = "NormalReceived"
	case PaddingReceived:
		pretty = "PaddingReceived"
	case TunnelReceived:
		pretty = "TunnelReceived"
	case NormalSent:
		pretty = "NormalSent"
	case PaddingSent:
		pretty = "PaddingSent"
	case TunnelSent:
		pretty = "TunnelSent"
	case BlockingBegin:
		pretty = "BlockingBegin"
	case BlockingEnd:
		pretty = "BlockingEnd"
	case TimerBegin:
		pretty = "TimerBegin"
	case TimerEnd:
		pretty = "TimerEnd"
	}
	return pretty
}
