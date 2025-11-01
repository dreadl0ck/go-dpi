// Package utils provides some useful utility functions to the library.
package utils

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// ReadDumpFile takes the path of a packet capture dump file and returns a
// channel that contains the packets in that file.
func ReadDumpFile(filename string) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.Default
	return packetSource.Packets(), nil
}
