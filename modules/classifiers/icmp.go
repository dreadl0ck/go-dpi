package classifiers

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// ICMPClassifier struct
type ICMPClassifier struct{}

// HeuristicClassify for ICMPClassifier
func (classifier ICMPClassifier) HeuristicClassify(flow *types.Flow) bool {
	hasICMP4Packet := checkFlowLayer(flow, layers.LayerTypeIPv4, func(layer gopacket.Layer) bool {
		ipLayer := layer.(*layers.IPv4)
		return ipLayer.Protocol == layers.IPProtocolICMPv4
	})
	hasICMP6Packet := checkFlowLayer(flow, layers.LayerTypeIPv6, func(layer gopacket.Layer) bool {
		ipLayer := layer.(*layers.IPv6)
		return ipLayer.NextHeader == layers.IPProtocolICMPv6
	})
	// if the flow has an ICMP(4|6) packet, then the flow type is ICMP
	return hasICMP4Packet || hasICMP6Packet
}

// GetProtocol returns the corresponding protocol
func (classifier ICMPClassifier) GetProtocol() types.Protocol {
	return types.ICMP
}
