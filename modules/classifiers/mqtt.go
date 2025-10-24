package classifiers

import (
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/dreadl0ck/go-dpi/types"
)

// MQTTClassifier struct
type MQTTClassifier struct{}

// HeuristicClassify for MQTTClassifier
func (classifier MQTTClassifier) HeuristicClassify(flow *types.Flow) bool {
	return checkFirstPayload(flow.GetPackets(), layers.LayerTypeTCP,
		func(payload []byte, packetsRest []gopacket.Packet) bool {
			if len(payload) < 4 {
				return false
			}
			//check Control packet (connect)
			if len(payload) < 6 {
				// at least 6 packets
				// 0x10 0x04 0x00 0x00 M Q
				return false
			}
			isValidPacket := payload[0] == 0x10
			isValidLength := int(payload[1]) == len(payload[2:])
			protocolNameStr := string(payload[4:])
			//check protocol name
			isValidMQTT := strings.HasPrefix(protocolNameStr, "MQ")
			return isValidMQTT && isValidLength && isValidPacket
		})
}

// GetProtocol returns the corresponding protocol
func (classifier MQTTClassifier) GetProtocol() types.Protocol {
	return types.MQTT
}
