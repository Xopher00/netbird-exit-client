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

// PaddingBytes is the wire bytes of dummy packets sent and received, which TxBytes and RxBytes include.
func (peer *Peer) PaddingBytes() (tx, rx uint64) {
	return peer.paddingTx.Load(), peer.paddingRx.Load()
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
}

func (peer *Peer) closeDaita() {
	if d := peer.daita.Swap(nil); d != nil {
		(*d).Close()
		tx, rx := peer.PaddingBytes()
		peer.device.log.Verbosef("%v - padding: dummy bytes sent %d, received %d", peer, tx, rx)
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
