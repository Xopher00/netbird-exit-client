//go:build !daita

package device

func (peer *Peer) EnableDaita(machines string, eventsCapacity uint, maxPaddingFrac float64, maxBlockingFrac float64) bool {
	peer.device.log.Errorf("%v - DAITA requested, but this build has no DAITA (build tag daita)", peer)
	return false
}
