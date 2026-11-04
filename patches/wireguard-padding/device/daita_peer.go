package device

// Counts of packets queued for a peer that a DAITA padding action with the replace flag may stand in for.

func (peer *Peer) getDaita() Daita {
	if d := peer.daita.Load(); d != nil {
		return *d
	}
	return nil
}

func (peer *Peer) DaitaEnabled() bool {
	return peer.daita.Load() != nil
}

// SetConstantPacketSize reports whether the setting changed.
func (peer *Peer) SetConstantPacketSize(on bool) bool {
	return peer.constantPacketSize.Swap(on) != on
}

func (peer *Peer) countOutbound(elem *QueueOutboundElement) {
	elem.countedFor = peer
	peer.outboundPackets.Add(1)
}

// outboundDone saturates instead of panicking like Mullvad's: ZeroAndFlushAll resets the counts while counted packets are still in flight.
func (peer *Peer) outboundDone() {
	saturatingDec(&peer.replacedPackets)
	saturatingDec(&peer.outboundPackets)
}

func (peer *Peer) ReplacedPacketsInc() {
	peer.replacedPackets.Add(1)
}

func (peer *Peer) HasReplaceablePackets() bool {
	return peer.outboundPackets.Load() > peer.replacedPackets.Load()
}

func (peer *Peer) resetOutboundAndReplaced() {
	peer.outboundPackets.Store(0)
	peer.replacedPackets.Store(0)
	if d := peer.getDaita(); d != nil {
		d.dropHeld(peer)
	}
}

func (peer *Peer) closeDaita() {
	if d := peer.daita.Swap(nil); d != nil {
		(*d).Close()
	}
}

func saturatingDec(v interface {
	Load() int32
	CompareAndSwap(old, new int32) bool
}) {
	for {
		cur := v.Load()
		if cur <= 0 || v.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}
