package main

import (
	"fmt"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
)

// This example demonstrates how to retrieve all supported categories and protocols
// for each classification system (LPI, nDPI, and Go classifiers).
func main() {
	fmt.Println("=== Supported Protocols and Categories ===")
	fmt.Println()

	// LPI (libprotoident) - supports both categories and protocols
	lpiWrapper := wrappers.NewLPIWrapper()

	lpiCategories := lpiWrapper.GetSupportedCategories()
	lpiProtocols := lpiWrapper.GetSupportedProtocols()

	fmt.Printf("LPI (libprotoident) supports:\n")
	fmt.Printf("  - %d categories\n", len(lpiCategories))
	fmt.Printf("  - %d protocols\n\n", len(lpiProtocols))

	// Optionally, print first few categories
	fmt.Println("  Sample categories:")
	for i, cat := range lpiCategories {
		if i >= 5 {
			fmt.Println("  ...")
			break
		}
		fmt.Printf("    - %s\n", cat)
	}
	fmt.Println()

	// Optionally, print first few protocols
	fmt.Println("  Sample protocols:")
	for i, proto := range lpiProtocols {
		if i >= 5 {
			fmt.Println("  ...")
			break
		}
		fmt.Printf("    - %s\n", proto)
	}
	fmt.Println()

	// nDPI - supports only protocols
	ndpiWrapper := wrappers.NewNDPIWrapper()

	ndpiProtocols := ndpiWrapper.GetSupportedProtocols()

	fmt.Printf("nDPI supports:\n")
	fmt.Printf("  - %d protocols\n\n", len(ndpiProtocols))

	// Optionally, print first few protocols
	fmt.Println("  Sample protocols:")
	for i, proto := range ndpiProtocols {
		if i >= 5 {
			fmt.Println("  ...")
			break
		}
		fmt.Printf("    - %s\n", proto)
	}
	fmt.Println()

	// Go classifiers - supports only protocols
	classifierModule := classifiers.NewClassifierModule()

	goProtocols := classifierModule.GetSupportedProtocols()

	fmt.Printf("Go classifiers support:\n")
	fmt.Printf("  - %d protocols\n\n", len(goProtocols))

	// Print all go classifier protocols (there aren't many)
	fmt.Println("  All protocols:")
	for _, proto := range goProtocols {
		fmt.Printf("    - %s\n", proto)
	}
}
