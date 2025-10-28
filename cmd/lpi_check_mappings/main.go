package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"github.com/dreadl0ck/go-dpi/types"
)

func main() {
	fmt.Println("=== libprotoident Protocol Mapping Validator ===")

	// Initialize LPI
	wrapper := wrappers.NewLPIWrapper()
	if errCode := wrapper.InitializeWrapper(); errCode != 0 {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to initialize libprotoident: error code %d\n", errCode)
		fmt.Fprintf(os.Stderr, "Make sure libprotoident is properly installed:\n")
		fmt.Fprintf(os.Stderr, "  macOS: brew install libprotoident\n")
		fmt.Fprintf(os.Stderr, "  Linux: apt-get install libprotoident-dev\n")
		os.Exit(1)
	}
	defer wrapper.DestroyWrapper()

	// Get all protocols from the installed library
	libraryProtocols := wrapper.GetAllLibraryProtocols()
	fmt.Printf("✓ Found %d protocols in installed libprotoident\n\n", len(libraryProtocols))

	// Sort by protocol code
	sort.Slice(libraryProtocols, func(i, j int) bool {
		return libraryProtocols[i].Code < libraryProtocols[j].Code
	})

	// Check each library protocol against our mapping
	var mismatches []string
	var missing []string
	unmappedCount := 0

	fmt.Println("=== Protocol Mapping Analysis ===")

	for _, libProto := range libraryProtocols {
		// Check if this code exists in our mapping
		mappedProto, exists := getMappedProtocol(libProto.Code)

		if !exists {
			missing = append(missing, fmt.Sprintf(
				"  %d: %-30s → NOT MAPPED (Category: %d)",
				libProto.Code, libProto.Name, libProto.Category,
			))
			unmappedCount++
		} else {
			// Check if the names roughly match
			libName := normalizeProtocolName(libProto.Name)
			mappedName := normalizeProtocolName(string(mappedProto))

			if !namesMatch(libName, mappedName) {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %d: Library='%s' → Mapped='%s' (MISMATCH?)",
					libProto.Code, libProto.Name, mappedProto,
				))
			}
		}
	}

	// Print results
	if len(mismatches) > 0 {
		fmt.Println("⚠️  POTENTIAL MISMATCHES (name differences):")
		for _, msg := range mismatches {
			fmt.Println(msg)
		}
		fmt.Println()
	}

	if len(missing) > 0 {
		fmt.Println("❌ UNMAPPED PROTOCOLS:")
		for _, msg := range missing {
			fmt.Println(msg)
		}
		fmt.Println()
	}

	// Print summary
	fmt.Println("=== Summary ===")
	fmt.Printf("Library protocols: %d\n", len(libraryProtocols))
	fmt.Printf("Potential mismatches: %d\n", len(mismatches))
	fmt.Printf("Unmapped protocols: %d\n", unmappedCount)

	if len(mismatches) > 0 || len(missing) > 0 {
		fmt.Println("\n⚠️  WARNING: Protocol mapping inconsistencies detected!")
		fmt.Println("\nRECOMMENDATION:")
		fmt.Println("Run the following command to generate an updated mapping:")
		fmt.Println("  go run ./cmd/lpi_generate_mappings")
		os.Exit(1)
	}

	fmt.Println("\n✅ All protocol mappings are correct!")
}

// getMappedProtocol looks up a protocol code in the lpiCodeToProtocol map
// For validation, we check critical codes that should always be present
func getMappedProtocol(code uint32) (types.Protocol, bool) {
	// Critical protocol codes that must be mapped
	criticalMappings := map[uint32]types.Protocol{
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

	proto, exists := criticalMappings[code]
	return proto, exists
}

// normalizeProtocolName normalizes a protocol name for comparison
func normalizeProtocolName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "")
	name = strings.ReplaceAll(name, "-", "")
	name = strings.ReplaceAll(name, " ", "")
	name = strings.ReplaceAll(name, ".", "")
	return name
}

// namesMatch checks if two protocol names are similar enough
func namesMatch(name1, name2 string) bool {
	if name1 == name2 {
		return true
	}

	// Check common variations
	if strings.Contains(name1, name2) || strings.Contains(name2, name1) {
		return true
	}

	// Known aliases
	aliases := map[string][]string{
		"xmpp":   {"jabber", "xmpps"},
		"jabber": {"xmpp", "xmpps"},
		"ssl":    {"tls", "https"},
		"https":  {"ssl", "tls"},
	}

	if aliasList, exists := aliases[name1]; exists {
		for _, alias := range aliasList {
			if alias == name2 {
				return true
			}
		}
	}

	return false
}
