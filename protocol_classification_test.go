package godpi

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/go-dpi/utils"
	"github.com/gopacket/gopacket"
)

var (
	testInitOnce sync.Once
	testInitErr  []error
)

// ensureDefaultModules ensures the default modules are set before initialization
func ensureDefaultModules() {
	// Import the default modules from the wrappers and classifiers packages
	moduleList = []types.Module{
		classifiers.NewClassifierModule(),
		wrappers.NewWrapperModule(),
	}
}

// TestCase represents a test case with a pcap file and expected protocol
type TestCase struct {
	filename         string
	expectedProtocol types.Protocol
	description      string
	minPacketsToTest int // Minimum packets that should be classified
}

// TestProtocolClassification tests protocol classification across all test pcap files
func TestProtocolClassification(t *testing.T) {
	testCases := []TestCase{
		{
			filename:         "godpi_example/dumps/http.cap",
			expectedProtocol: types.HTTP,
			description:      "HTTP traffic",
			minPacketsToTest: 10,
		},
		{
			filename:         "godpi_example/dumps/https.cap",
			expectedProtocol: types.TLS,
			description:      "HTTPS/TLS traffic",
			minPacketsToTest: 5,
		},
		{
			filename:         "godpi_example/dumps/ssh.pcap",
			expectedProtocol: types.SSH,
			description:      "SSH traffic",
			minPacketsToTest: 1, // This pcap has special characteristics
		},
		{
			filename:         "godpi_example/dumps/ftp.pcap",
			expectedProtocol: types.FTP_CONTROL,
			description:      "FTP traffic",
			minPacketsToTest: 5,
		},
		{
			filename:         "godpi_example/dumps/smtp.pcap",
			expectedProtocol: types.MAIL_SMTP,
			description:      "SMTP traffic",
			minPacketsToTest: 5,
		},
		{
			filename:         "godpi_example/dumps/rdp.pcap",
			expectedProtocol: types.RDP,
			description:      "RDP traffic",
			minPacketsToTest: 5,
		},
		{
			filename:         "godpi_example/dumps/bittorrent.pcap",
			expectedProtocol: types.BITTORRENT,
			description:      "BitTorrent traffic",
			minPacketsToTest: 5,
		},
		{
			filename:         "godpi_example/dumps/mqtt.pcap",
			expectedProtocol: types.MQTT,
			description:      "MQTT traffic",
			minPacketsToTest: 3,
		},
		{
			filename:         "godpi_example/dumps/jabber.pcap",
			expectedProtocol: types.JABBER,
			description:      "Jabber/XMPP traffic",
			minPacketsToTest: 1,
		},
		// Note: DNS and ICMPv6 pcaps may have special characteristics or require
		// specific wrapper support that is not currently available
		{
			filename:         "godpi_example/dumps/netbios.pcap",
			expectedProtocol: types.NETBIOS,
			description:      "NetBIOS traffic",
			minPacketsToTest: 5,
		},
	}

	// Initialize the library once across all tests using sync.Once
	testInitOnce.Do(func() {
		ensureDefaultModules()
		testInitErr = Initialize()
	})
	if len(testInitErr) != 0 {
		t.Logf("Initialization warnings/errors:")
		for _, err := range testInitErr {
			t.Logf("  - %v", err)
		}
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			testProtocolClassification(t, tc)
		})
	}
}

// testProtocolClassification tests a single pcap file
func testProtocolClassification(t *testing.T, tc TestCase) {
	// Read the pcap file
	packetChannel, err := utils.ReadDumpFile(tc.filename)
	if err != nil {
		t.Fatalf("Failed to read pcap file %s: %v", tc.filename, err)
	}

	// Track results from different sources
	detectionsBySource := make(map[types.ClassificationSource]int)
	totalPackets := 0
	totalClassified := 0
	classifiedProtocols := make(map[types.Protocol]int)

	// Process all packets
	for packet := range packetChannel {
		totalPackets++
		flow, _ := GetPacketFlow(packet)

		// Get results from all modules to see which ones detect the protocol
		results := ClassifyFlowAllModules(flow)

		for _, result := range results {
			if result.Protocol != types.Unknown {
				if result.Protocol == tc.expectedProtocol {
					detectionsBySource[result.Source]++
				}
				classifiedProtocols[result.Protocol]++
				totalClassified++
			}
		}
	}

	// Log summary
	t.Logf("File: %s", filepath.Base(tc.filename))
	t.Logf("Total packets: %d", totalPackets)
	t.Logf("Expected protocol: %s", tc.expectedProtocol)
	t.Logf("All detected protocols: %v", classifiedProtocols)
	t.Logf("Expected protocol detections by source:")
	for source, count := range detectionsBySource {
		t.Logf("  - %s: %d packets", source, count)
	}

	// Verify that at least one wrapper detected the expected protocol
	totalExpectedDetections := 0
	for _, count := range detectionsBySource {
		totalExpectedDetections += count
	}

	if totalExpectedDetections == 0 {
		t.Errorf("Expected protocol %s was not detected by any wrapper", tc.expectedProtocol)
		return
	}

	// Verify we detected enough packets of the expected protocol
	if totalExpectedDetections < tc.minPacketsToTest {
		t.Errorf("Expected at least %d packets to be classified as %s, but only got %d",
			tc.minPacketsToTest, tc.expectedProtocol, totalExpectedDetections)
		return
	}

	// Check specific wrappers
	hasNDPI := detectionsBySource["nDPI"] > 0
	hasLPI := detectionsBySource["libprotoident"] > 0
	hasGoDPI := detectionsBySource["go-dpi"] > 0

	if !hasNDPI && !hasLPI && !hasGoDPI {
		t.Errorf("No wrapper detected the expected protocol %s", tc.expectedProtocol)
		return
	}

	// Log which wrappers successfully detected the protocol
	var detectedBy []string
	if hasNDPI {
		detectedBy = append(detectedBy, "nDPI")
	}
	if hasLPI {
		detectedBy = append(detectedBy, "libprotoident")
	}
	if hasGoDPI {
		detectedBy = append(detectedBy, "go-dpi")
	}
	t.Logf("✓ Protocol %s successfully detected by: %v", tc.expectedProtocol, detectedBy)
}

// TestIndividualWrapperCapabilities tests each wrapper individually to document their capabilities
func TestIndividualWrapperCapabilities(t *testing.T) {
	testFiles := map[string]types.Protocol{
		"godpi_example/dumps/http.cap":        types.HTTP,
		"godpi_example/dumps/https.cap":       types.TLS,
		"godpi_example/dumps/ssh.pcap":        types.SSH,
		"godpi_example/dumps/ftp.pcap":        types.FTP_CONTROL,
		"godpi_example/dumps/smtp.pcap":       types.MAIL_SMTP,
		"godpi_example/dumps/rdp.pcap":        types.RDP,
		"godpi_example/dumps/bittorrent.pcap": types.BITTORRENT,
		"godpi_example/dumps/mqtt.pcap":       types.MQTT,
		"godpi_example/dumps/jabber.pcap":     types.JABBER,
	}

	// Initialize the library once across all tests using sync.Once
	testInitOnce.Do(func() {
		testInitErr = Initialize()
	})
	if len(testInitErr) != 0 {
		t.Logf("Initialization warnings/errors:")
		for _, err := range testInitErr {
			t.Logf("  - %v", err)
		}
	}

	// Create a capabilities matrix
	capabilities := make(map[types.ClassificationSource]map[types.Protocol]bool)
	capabilities["nDPI"] = make(map[types.Protocol]bool)
	capabilities["libprotoident"] = make(map[types.Protocol]bool)
	capabilities["go-dpi"] = make(map[types.Protocol]bool)

	for filename, expectedProto := range testFiles {
		packetChannel, err := utils.ReadDumpFile(filename)
		if err != nil {
			t.Logf("Warning: Failed to read %s: %v", filename, err)
			continue
		}

		sourceDetected := make(map[types.ClassificationSource]bool)

		for packet := range packetChannel {
			flow, _ := GetPacketFlow(packet)
			results := ClassifyFlowAllModules(flow)

			for _, result := range results {
				if result.Protocol == expectedProto {
					sourceDetected[result.Source] = true
				}
			}
		}

		// Record capabilities
		for source := range sourceDetected {
			capabilities[source][expectedProto] = true
		}

		// Flush flows between files
		types.FlushTrackedFlows()
	}

	// Print capabilities matrix
	t.Logf("\n=== Wrapper Capabilities Matrix ===")
	protocols := []types.Protocol{
		types.HTTP, types.TLS, types.SSH, types.FTP_CONTROL,
		types.MAIL_SMTP, types.RDP, types.BITTORRENT, types.MQTT, types.JABBER,
	}

	for _, proto := range protocols {
		supports := []string{}
		for _, source := range []types.ClassificationSource{"nDPI", "libprotoident", "go-dpi"} {
			if capabilities[source][proto] {
				supports = append(supports, string(source))
			}
		}
		if len(supports) > 0 {
			t.Logf("%-20s: %v", proto, supports)
		} else {
			t.Logf("%-20s: (none)", proto)
		}
	}
}

// TestNDPITimestampFix verifies that nDPI receives correct timestamps
func TestNDPITimestampFix(t *testing.T) {
	// Initialize the library once across all tests using sync.Once
	testInitOnce.Do(func() {
		testInitErr = Initialize()
	})
	if len(testInitErr) != 0 {
		t.Logf("Initialization warnings/errors:")
		for _, err := range testInitErr {
			t.Logf("  - %v", err)
		}
	}

	// Test with HTTP pcap - should be detected by nDPI
	packetChannel, err := utils.ReadDumpFile("godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatalf("Failed to read http.cap: %v", err)
	}

	ndpiDetections := 0
	totalPackets := 0

	for packet := range packetChannel {
		totalPackets++
		flow, _ := GetPacketFlow(packet)
		results := ClassifyFlowAllModules(flow)

		for _, result := range results {
			if result.Source == "nDPI" && result.Protocol == types.HTTP {
				ndpiDetections++
			}
		}
	}

	t.Logf("Total packets: %d", totalPackets)
	t.Logf("nDPI HTTP detections: %d", ndpiDetections)

	if ndpiDetections == 0 {
		t.Error("nDPI did not detect any HTTP packets - timestamp fix may not be working")
	} else {
		t.Logf("✓ nDPI successfully detected HTTP traffic (%d packets)", ndpiDetections)
	}
}

// BenchmarkProtocolClassification benchmarks the classification performance
func BenchmarkProtocolClassification(b *testing.B) {
	// Initialize the library once across all tests using sync.Once
	testInitOnce.Do(func() {
		testInitErr = Initialize()
	})
	if len(testInitErr) != 0 {
		b.Logf("Initialization warnings/errors:")
		for _, err := range testInitErr {
			b.Logf("  - %v", err)
		}
	}

	// Load packets once
	packetChannel, err := utils.ReadDumpFile("godpi_example/dumps/http.cap")
	if err != nil {
		b.Fatalf("Failed to read http.cap: %v", err)
	}

	// Collect packets into slice
	var packets []gopacket.Packet
	for packet := range packetChannel {
		packets = append(packets, packet)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Process each packet
		for _, pkt := range packets {
			flow, _ := GetPacketFlow(pkt)
			_ = ClassifyFlow(flow)
		}

		// Flush flows between iterations
		types.FlushTrackedFlows()
	}

	b.Logf("Processed %d packets per iteration", len(packets))
}
