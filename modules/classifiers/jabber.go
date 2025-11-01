package classifiers

import (
	"regexp"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// JABBERClassifier struct
type JABBERClassifier struct{}

// HeuristicClassify for JABBERClassifier
func (classifier JABBERClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []gopacket.Packet) bool {
			payloadStr := string(payload)
			// XMPP/Jabber connections start with an XML declaration
			// followed by stream:stream with jabber namespace (may be in next packet)
			hasXMLDecl, _ := regexp.MatchString("^\\s*<\\?xml\\s+version=['\"](\\d+\\.\\d+)['\"]", payloadStr)
			if !hasXMLDecl {
				return false
			}
			
			// Check if jabber-specific content is in the first packet
			hasJabberNS, _ := regexp.MatchString("jabber:(client|server|component)", payloadStr)
			if hasJabberNS {
				return true
			}
			
			// If not in first packet, check the next TCP packet for jabber namespace
			return checkFirstPayload(packetsRest, layers.LayerTypeTCP,
				func(nextPayload []byte, _ []gopacket.Packet) bool {
					nextPayloadStr := string(nextPayload)
					hasJabberInNext, _ := regexp.MatchString("jabber:(client|server|component)", nextPayloadStr)
					return hasJabberInNext
				})
		})
}

// GetProtocol returns the corresponding protocol
func (classifier JABBERClassifier) GetProtocol() types.Protocol {
	return types.JABBER
}
