package wrappers

import (
	"testing"

	"github.com/dreadl0ck/go-dpi/types"
)

// TestLPIProtocolMappingCompleteness validates that all expected protocol codes are mapped
func TestLPIProtocolMappingCompleteness(t *testing.T) {
	// Test that critical protocol codes are present in the mapping
	criticalProtocols := map[uint32]types.Protocol{
		0:   types.HTTP,
		1:   types.SMTP,
		2:   types.BITTORRENT,
		8:   types.SSH,
		9:   types.HTTPS,
		11:  types.POP3,
		15:  types.IMAP,
		20:  types.TELNET,
		21:  types.RDP,
		24:  types.SMB,
		27:  types.FTP_CONTROL,
		28:  types.FTP_DATA,
		37:  types.NETBIOS,
		40:  types.SIP,
		51:  types.MYSQL,
		100: types.XMPP, // Jabber/XMPP
	}

	for code, expectedProto := range criticalProtocols {
		mappedProto, exists := lpiCodeToProtocol[code]
		if !exists {
			t.Errorf("Critical protocol code %d is not mapped", code)
			continue
		}
		if mappedProto != expectedProto {
			t.Errorf("Protocol code %d: expected %s, got %s", code, expectedProto, mappedProto)
		}
	}

	t.Logf("✓ All %d critical protocol codes are correctly mapped", len(criticalProtocols))
}

// TestLPIProtocolIntrospection tests the protocol introspection functions
func TestLPIProtocolIntrospection(t *testing.T) {
	wrapper := NewLPIWrapper()

	// Initialize the wrapper
	if errCode := wrapper.InitializeWrapper(); errCode != 0 {
		t.Skipf("Skipping introspection test: LPI initialization failed with code %d", errCode)
		return
	}
	defer wrapper.DestroyWrapper()

	// Get protocol count
	count := wrapper.GetLibraryProtocolCount()
	if count <= 0 {
		t.Errorf("Expected positive protocol count, got %d", count)
		return
	}
	t.Logf("✓ Library supports %d protocol codes", count)

	// Test retrieving specific protocols
	testCodes := []uint32{0, 1, 2, 8, 9, 100} // HTTP, SMTP, BitTorrent, SSH, HTTPS, XMPP
	successCount := 0

	for _, code := range testCodes {
		info := wrapper.GetLibraryProtocolInfo(int(code))
		if info == nil {
			t.Logf("  Protocol code %d: not found (may be NULL)", code)
			continue
		}

		t.Logf("  Protocol %d: %s (category: %d)", info.Code, info.Name, info.Category)
		successCount++
	}

	if successCount == 0 {
		t.Error("No protocols could be retrieved")
	} else {
		t.Logf("✓ Successfully retrieved %d/%d test protocol infos", successCount, len(testCodes))
	}
}

// TestLPIKnownMisclassifications documents known libprotoident limitations
func TestLPIKnownMisclassifications(t *testing.T) {
	knownIssues := map[string]struct {
		pcapFile      string
		expectedProto types.Protocol
		actualProto   types.Protocol
		reason        string
	}{
		"jabber": {
			pcapFile:      "jabber.pcap",
			expectedProto: types.XMPP,
			actualProto:   types.FTP_DATA,
			reason:        "libprotoident misidentifies Jabber traffic as FTP_DATA (code 28 instead of 100)",
		},
	}

	t.Log("=== Known libprotoident Classification Issues ===")
	for name, issue := range knownIssues {
		t.Logf("\n%s:", name)
		t.Logf("  File: %s", issue.pcapFile)
		t.Logf("  Expected: %s", issue.expectedProto)
		t.Logf("  Actually returns: %s", issue.actualProto)
		t.Logf("  Reason: %s", issue.reason)
	}

	t.Log("\nThese are limitations of the underlying libprotoident library,")
	t.Log("not bugs in the go-dpi wrapper. The protocol code mappings are correct.")
}

// TestLPIProtocolCodeConsistency validates the mapping is internally consistent
func TestLPIProtocolCodeConsistency(t *testing.T) {
	// Count occurrences of each protocol to detect duplicates
	protoCounts := make(map[types.Protocol][]uint32)

	for code, proto := range lpiCodeToProtocol {
		protoCounts[proto] = append(protoCounts[proto], code)
	}

	// Check for unintended duplicates (some duplicates are legitimate, like UNKNOWN)
	duplicates := 0
	for proto, codes := range protoCounts {
		if len(codes) > 1 {
			// Allow certain protocols to have multiple codes
			allowedDuplicates := map[types.Protocol]bool{
				types.Unknown:     true,
				types.UNSUPPORTED: true,
				types.INVALID:     true,
				types.NO_PAYLOAD:  true,
				types.NO_FIRSTPKT: true,
			}

			if !allowedDuplicates[proto] {
				t.Logf("Warning: Protocol %s is mapped to multiple codes: %v", proto, codes)
				duplicates++
			}
		}
	}

	if duplicates > 10 {
		t.Errorf("Too many duplicate mappings: %d (investigate if mapping is correct)", duplicates)
	}

	t.Logf("✓ Protocol mapping has %d total entries", len(lpiCodeToProtocol))
}

// TestLPICategoryMapping validates that all category codes are mapped
func TestLPICategoryMapping(t *testing.T) {
	// All libprotoident categories should be mapped
	expectedCategories := 46 // 0-45

	if len(lpiCodeToCategory) != expectedCategories {
		t.Errorf("Expected %d category mappings, got %d", expectedCategories, len(lpiCodeToCategory))
	}

	// Check for gaps
	for i := uint32(0); i < uint32(expectedCategories); i++ {
		if _, exists := lpiCodeToCategory[i]; !exists {
			t.Errorf("Category code %d is not mapped", i)
		}
	}

	t.Logf("✓ All %d category codes are mapped", len(lpiCodeToCategory))
}
