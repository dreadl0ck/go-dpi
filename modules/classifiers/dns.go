package classifiers

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// DNSClassifier struct
type DNSClassifier struct{}

// HeuristicClassify for DNSClassifier
func (classifier DNSClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFlowLayer(flow, layers.LayerTypeUDP, func(layer gopacket.Layer) (detected bool) {
		defer func() {
			if err := recover(); err != nil {
				detected = false
			}
		}()
		dns := layers.DNS{}
		// Decode directly using DNS layer's DecodeFromBytes
		// Pass nil as the decoder since we're not using a DecodingLayerParser
		err := dns.DecodeFromBytes(layer.LayerPayload(), gopacket.NilDecodeFeedback)
		// attempt to decode layer as DNS packet using gopacket and return
		// whether it was successful
		detected = err == nil
		return
	})
}

// GetProtocol returns the corresponding protocol
func (classifier DNSClassifier) GetProtocol() types.Protocol {
	return types.DNS
}
