package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/go-dpi/utils"
)

func main() {
	var (
		count, idCount int
		packetChannel  <-chan gopacket.Packet
		err            error
		protoCounts = make(map[types.Protocol]int)
		filename = flag.String("r", "godpi_example/dumps/http.cap", "File to read packets from")
		device = flag.String("device", "", "Device to watch for packets")
	)

	flag.Parse()

	if *device != "" {
		// check if interface was given
		handle, deverr := pcap.OpenLive(*device, 1514, false, time.Duration(-1))
		if deverr != nil {
			fmt.Println("Error opening device:", deverr)
			return
		}
		packetChannel = gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	} else if _, ferr := os.Stat(*filename); !os.IsNotExist(ferr) {
		// check if file exists
		packetChannel, err = utils.ReadDumpFile(*filename)
	} else {
		fmt.Println("File does not exist:", *filename)
		return
	}

	initErrs := godpi.Initialize()
	if len(initErrs) != 0 {
		for _, err := range initErrs {
			fmt.Println(err)
		}
	}

	nDPI := wrappers.NewNDPIWrapper()
	switch errCode := nDPI.InitializeWrapper(); errCode {
	case 0:
		// all good
		fmt.Println("nDPI OK")
	case -0x1000: // errorLibraryDisabled
		// do nothing if library is disabled
		log.Fatal("nDPI is disabled")
	default:
		log.Fatal("nDPI initialization returned error code: ", errCode)
	}
	fmt.Println("Init done")

	defer func() {
		if err := nDPI.DestroyWrapper(); err != nil {
			fmt.Println(err)
		}
		fmt.Println()
		fmt.Println("Number of packets:", count)
		fmt.Println("Number of packets identified:", idCount)
		fmt.Println("Protocols identified:\n", protoCounts)
	}()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	intSignal := false

	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	count = 0
	for packet := range packetChannel {
		fmt.Printf("Packet #%d: ", count+1)
		flow, isNew := godpi.GetPacketFlow(packet)
		result := godpi.ClassifyFlow(flow)
		if result.Protocol != types.Unknown {
			fmt.Print(result)
			idCount++
			protoCounts[result.Protocol]++
		} else {
			fmt.Print("Could not identify")
		}
		if isNew {
			fmt.Println(" (new flow)")
		} else {
			fmt.Println()
		}

		select {
		case <-signalChannel:
			fmt.Println("Received interrupt signal")
			intSignal = true
		default:
		}
		if intSignal {
			break
		}
		count++
	}
}
