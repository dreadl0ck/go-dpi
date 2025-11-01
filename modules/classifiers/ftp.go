package classifiers

import (
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// FTPClassifier struct
type FTPClassifier struct{}

// HeuristicClassify for FTPClassifier
func (classifier FTPClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []gopacket.Packet) bool {
			payloadStr := string(payload)
			hasValid220 := false
			for _, line := range strings.Split(payloadStr, "\n") {
				if len(line) > 0 {
					if strings.HasPrefix(line, "220") {
						hasValid220 = true
					} else {
						// Non-220 line found, not FTP
						return false
					}
				}
			}
			// Must have at least one valid 220 line
			if !hasValid220 {
				return false
			}
			return checkFirstPayload(packetsRest, layers.LayerTypeTCP,
				func(payload []byte, _ []gopacket.Packet) bool {
					payloadStr := string(payload)
					return strings.HasPrefix(payloadStr, "USER ") &&
						strings.HasSuffix(payloadStr, "\n")
				})
		})
}

// GetProtocol returns the corresponding protocol
func (classifier FTPClassifier) GetProtocol() types.Protocol {
	return types.FTP
}
