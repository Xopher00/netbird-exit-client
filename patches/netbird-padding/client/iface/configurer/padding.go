package configurer

import (
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

const (
	// Newline-separated Maybenot machines; set by Hopper on both ends of its tunnel.
	envPaddingMachines = "NB_DAITA_MACHINES"
	envFullSizePackets = "NB_DAITA_FULL_SIZE"

	// Maybenot's event buffer, and the largest share of traffic padding and blocking may add (1.0: no limit).
	paddingEventsCapacity = 1024
	maxPaddingFrac        = 1.0
	maxBlockingFrac       = 1.0
)

// applyPadding is called on every peer update; a peer whose padding already runs is left alone.
func applyPadding(dev *wgbackend.Device, key wgtypes.Key) {
	machines := os.Getenv(envPaddingMachines)
	fullSize := os.Getenv(envFullSizePackets) == "true"
	if machines == "" && !fullSize {
		return
	}
	peer := dev.LookupPeer(wgbackend.NoisePublicKey(key))
	if peer == nil {
		return
	}
	if peer.SetConstantPacketSize(fullSize) && fullSize {
		log.Infof("full-size packets on for peer %s", key)
	}
	if machines != "" && !peer.DaitaEnabled() && peer.EnableDaita(machines, paddingEventsCapacity, maxPaddingFrac, maxBlockingFrac) {
		log.Infof("padding on for peer %s", key)
	}
}
