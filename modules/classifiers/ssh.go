package classifiers

import (
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// SSHClassifier struct
type SSHClassifier struct{}

// HeuristicClassify for SSHClassifier
func (classifier SSHClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, _ []gopacket.Packet) bool {
			payloadStr := string(payload)
			// SSH banner must end with newline
			if !strings.HasSuffix(payloadStr, "\n") {
				return false
			}
			// SSH banner format: "SSH-protoversion-softwareversion SP comments CR LF"
			// Must start with "SSH-" followed by version (e.g., "SSH-2.0-OpenSSH_7.4")
			return strings.HasPrefix(payloadStr, "SSH-")
		})
}

// GetProtocol returns the corresponding protocol
func (classifier SSHClassifier) GetProtocol() types.Protocol {
	return types.SSH
}
