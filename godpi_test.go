package godpi

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/go-dpi/utils"
)

func TestInitializeError(t *testing.T) {
	module := &types.MockModule{InitSuccess: false}
	SetModules([]types.Module{module})
	errors := Initialize()
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from initializing, got %d", errNum)
	}
	if module.InitCalled != 1 {
		t.Error("Initialize not called once")
	}
	result := ClassifyFlow(types.NewFlow())
	if module.ClassifyCalled != 0 {
		t.Error("Classify called on errored module")
	}
	if result.Protocol != types.Unknown || result.Source != types.NoSource {
		t.Errorf("Expected no result, got protocol %v from source %v", result.Protocol, result.Source)
	}
	Destroy()
	if module.DestroyCalled != 0 {
		t.Error("Destroy called on errored module")
	}
}

func TestDestroyError(t *testing.T) {
	module := &types.MockModule{InitSuccess: true, DestroySuccess: false}
	SetModules([]types.Module{module})
	Initialize()
	errors := Destroy()
	if module.DestroyCalled != 1 {
		t.Error("Destroy not called on module")
	}
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from destroying, got %d", errNum)
	}
	errors = Destroy()
	if module.DestroyCalled != 2 {
		t.Error("Destroy not called again on module")
	}
	if errNum := len(errors); errNum != 1 {
		t.Errorf("Expected one error to be returned from destroying the second time, got %d", errNum)
	}
}

func TestClassifyFlow(t *testing.T) {
	noClsModule := &types.MockModule{InitSuccess: true, ClassifySuccess: false, DestroySuccess: true, SourceName: "module1"}
	clsModule := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module2"}
	clsModule2 := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module3"}
	SetModules([]types.Module{noClsModule, clsModule, clsModule2})
	errors := Initialize()
	if errNum := len(errors); errNum != 0 {
		t.Errorf("Expected no errors to be returned from initializing, got %d", errNum)
	}
	if noClsModule.InitCalled != 1 || clsModule.InitCalled != 1 || clsModule2.InitCalled != 1 {
		t.Error("Initialize not called on all modules once")
	}
	// Create a flow with enough packets to meet MinPacketsForClassification requirement
	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	for i := 0; i < types.MinPacketsForClassification; i++ {
		packet := <-packetChan
		flow.AddPacket(packet)
	}
	result := ClassifyFlow(flow)
	// With sequential execution, modules are tried in priority order
	// so module2 (first successful module) should be used
	if result.Protocol != types.HTTP {
		t.Errorf("Expected HTTP protocol, got protocol %v from source %v", result.Protocol, result.Source)
	}
	if result.Source != "module2" {
		t.Errorf("Expected result from module2 (first successful module in priority order), got source %v", result.Source)
	}
	// Verify that module1 was tried but failed, and module3 was never tried (because module2 succeeded)
	if noClsModule.ClassifyCalled != 1 {
		t.Errorf("Expected module1 (unsuccessful) to be called once, was called %d times", noClsModule.ClassifyCalled)
	}
	if clsModule.ClassifyCalled != 1 {
		t.Errorf("Expected module2 (successful) to be called once, was called %d times", clsModule.ClassifyCalled)
	}
	if clsModule2.ClassifyCalled != 0 {
		t.Errorf("Expected module3 to not be called (module2 succeeded first), was called %d times", clsModule2.ClassifyCalled)
	}

	// Create another flow with enough packets for ClassifyFlowAllModules
	flow2 := types.NewFlow()
	for i := 0; i < types.MinPacketsForClassification; i++ {
		packet := <-packetChan
		flow2.AddPacket(packet)
	}
	results := ClassifyFlowAllModules(flow2)
	// ClassifyFlowAllModules runs sequentially and deduplicates by protocol
	// Both module2 and module3 return HTTP, but only the first (module2) should be included
	if len(results) != 1 {
		t.Errorf("Expected 1 result from ClassifyFlowAllModules (deduplicated), got %d", len(results))
	}
	if len(results) > 0 {
		if results[0].Protocol != types.HTTP {
			t.Errorf("Expected HTTP protocol in results, got %v", results[0].Protocol)
		}
		// With sequential execution and deduplication, only module2 (first successful) should be in results
		if results[0].Source != "module2" {
			t.Errorf("Expected result from module2 (first in priority order), got source %v", results[0].Source)
		}
	}
	Destroy()
	if noClsModule.DestroyCalled != 1 || clsModule.DestroyCalled != 1 || clsModule2.DestroyCalled != 1 {
		t.Error("Destroy not called on all modules")
	}
}

func TestDoubleInitialize(t *testing.T) {
	module := &types.MockModule{InitSuccess: true}
	SetModules([]types.Module{module})
	Initialize()
	if module.InitCalled != 1 {
		t.Error("Initialize not called once")
	}
	Initialize()
	if module.InitCalled != 1 {
		t.Error("Initialize called again for initialized module")
	}
}

func TestGetPacketFlow(t *testing.T) {
	dumpPackets, err := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	packet := <-dumpPackets
	flowFirst, isNew := GetPacketFlow(packet)
	if !isNew {
		t.Error("Not new flow for first packet")
	}
	for i := 0; i < 3; i++ {
		packet := <-dumpPackets
		flowNext, isNew := GetPacketFlow(packet)
		// TODO: fix incorrect tests
		if isNew {
			t.Error("New flow returned for packet in existing flow")
		}
		if flowNext != flowFirst {
			t.Error("Wrong existing flow returned")
		}
	}
}

func TestSetCacheExpiration(t *testing.T) {
	SetCacheExpiration(-1)
	if cacheExpiration != -1 {
		t.Errorf("Cache expiration not set: expected -1, found %v", cacheExpiration)
	}
}

// TestClassifyFlowAllModules verifies that ClassifyFlowAllModules runs all modules
// sequentially in priority order and deduplicates results by protocol.
func TestClassifyFlowAllModules(t *testing.T) {
	module1 := &types.MockModule{InitSuccess: true, ClassifySuccess: false, DestroySuccess: true, SourceName: "module1"}
	module2 := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module2"}
	module3 := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module3"}

	SetModules([]types.Module{module1, module2, module3})
	Initialize()
	defer Destroy()

	// Create a flow with enough packets
	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	for i := 0; i < types.MinPacketsForClassification; i++ {
		packet := <-packetChan
		flow.AddPacket(packet)
	}

	// ClassifyFlowAllModules should run ALL modules (not stop at first success)
	results := ClassifyFlowAllModules(flow)

	// Verify all modules were called (unlike ClassifyFlow which stops at first success)
	if module1.ClassifyCalled != 1 {
		t.Errorf("Expected module1 to be called once, was called %d times", module1.ClassifyCalled)
	}
	if module2.ClassifyCalled != 1 {
		t.Errorf("Expected module2 to be called once, was called %d times", module2.ClassifyCalled)
	}
	if module3.ClassifyCalled != 1 {
		t.Errorf("Expected module3 to be called once (ClassifyFlowAllModules runs all), was called %d times", module3.ClassifyCalled)
	}

	// Both module2 and module3 return HTTP, but deduplication should keep only the first
	if len(results) != 1 {
		t.Errorf("Expected 1 deduplicated result, got %d", len(results))
	}

	if len(results) > 0 {
		if results[0].Protocol != types.HTTP {
			t.Errorf("Expected HTTP protocol, got %v", results[0].Protocol)
		}
		// With deduplication by protocol, only module2 (first to return HTTP) should be in results
		if results[0].Source != "module2" {
			t.Errorf("Expected source module2 (first in priority order), got %v", results[0].Source)
		}
	}

	t.Logf("✓ ClassifyFlowAllModules verified: All %d modules called sequentially, %d deduplicated result returned",
		3, len(results))
}

// TestClassifyFlowCaching verifies that once a flow is classified, the result
// is cached and returned on subsequent calls without recalculating.
func TestClassifyFlowCaching(t *testing.T) {
	module1 := &types.MockModule{InitSuccess: true, ClassifySuccess: false, DestroySuccess: true, SourceName: "module1"}
	module2 := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module2"}
	module3 := &types.MockModule{InitSuccess: true, ClassifySuccess: true, DestroySuccess: true, SourceName: "module3"}

	SetModules([]types.Module{module1, module2, module3})
	Initialize()
	defer Destroy()

	// Create a flow with enough packets
	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	for i := 0; i < types.MinPacketsForClassification; i++ {
		packet := <-packetChan
		flow.AddPacket(packet)
	}

	// First call should classify the flow
	result1 := ClassifyFlow(flow)
	if result1.Protocol != types.HTTP {
		t.Errorf("Expected HTTP protocol, got %v", result1.Protocol)
	}
	if result1.Source != "module2" {
		t.Errorf("Expected source module2, got %v", result1.Source)
	}

	// Verify module1 was called (failed), module2 was called (succeeded), module3 was not called
	if module1.ClassifyCalled != 1 {
		t.Errorf("Expected module1 to be called once on first classification, was called %d times", module1.ClassifyCalled)
	}
	if module2.ClassifyCalled != 1 {
		t.Errorf("Expected module2 to be called once on first classification, was called %d times", module2.ClassifyCalled)
	}
	if module3.ClassifyCalled != 0 {
		t.Errorf("Expected module3 to not be called (module2 succeeded), was called %d times", module3.ClassifyCalled)
	}

	// Second call should return cached result without calling any modules
	result2 := ClassifyFlow(flow)
	if result2.Protocol != types.HTTP {
		t.Errorf("Expected cached HTTP protocol, got %v", result2.Protocol)
	}
	if result2.Source != "module2" {
		t.Errorf("Expected cached source module2, got %v", result2.Source)
	}

	// Verify no modules were called again (cached result was used)
	if module1.ClassifyCalled != 1 {
		t.Errorf("Expected module1 to still be called only once (cache hit), was called %d times", module1.ClassifyCalled)
	}
	if module2.ClassifyCalled != 1 {
		t.Errorf("Expected module2 to still be called only once (cache hit), was called %d times", module2.ClassifyCalled)
	}
	if module3.ClassifyCalled != 0 {
		t.Errorf("Expected module3 to still not be called (cache hit), was called %d times", module3.ClassifyCalled)
	}

	// Third call to verify caching continues to work
	result3 := ClassifyFlow(flow)
	if result3.Protocol != types.HTTP || result3.Source != "module2" {
		t.Errorf("Expected cached result on third call, got protocol %v from source %v", result3.Protocol, result3.Source)
	}

	// Verify counters haven't changed
	if module1.ClassifyCalled != 1 || module2.ClassifyCalled != 1 || module3.ClassifyCalled != 0 {
		t.Error("Modules were called again despite cached result being available")
	}

	t.Logf("✓ Caching verified: Flow classified once, cached result returned on %d subsequent calls without recalculation", 2)
}

// TestDetectionMatrix creates a comprehensive matrix showing which detection
// framework (go-dpi, LPI, nDPI) detects which protocols across all dump files.
// Results are saved to detection_matrix.txt for documentation.
func TestDetectionMatrix(t *testing.T) {
	dumpsDir := "./godpi_example/dumps/"
	outputFile := "detection_matrix.txt"

	// Initialize with all modules
	Initialize()
	defer Destroy()

	// Create output file
	var output strings.Builder

	// Write header with explanations
	header := `
================================================================================
                        PROTOCOL DETECTION MATRIX
================================================================================

This file shows which DPI (Deep Packet Inspection) frameworks detect which 
protocols across all test dump files.

DETECTION FRAMEWORKS (in priority order):
------------------------------------------
1. go-dpi      - Fast heuristic-based classifiers written in Go
2. LPI         - libprotoident (Lightweight Payload Inspection)
3. nDPI        - ntop's Deep Packet Inspection library

PRIORITY ORDER:
---------------
The frameworks are executed sequentially in the order listed above. This means:
- go-dpi classifiers run first (fastest, lowest overhead)
- If go-dpi doesn't detect the protocol, LPI is tried next
- If neither go-dpi nor LPI detect it, nDPI is tried last

DETECTION METHODS:
------------------
• ClassifyFlow:
  Stops at the FIRST framework that successfully detects a protocol.
  Returns only one result per flow (from the highest-priority framework).
  This is the standard/recommended method for production use.
  
• ClassifyFlowAll:
  Runs ALL frameworks and collects results from each.
  Multiple frameworks may detect the same flow (shown with + separator).
  Useful for debugging, comparison, and understanding detection capabilities.
  Results are deduplicated by protocol (first detection wins).

HOW TO READ THE RESULTS:
-------------------------
Format: PROTOCOL(source) or PROTOCOL(source1+source2+source3)

Examples:
  HTTP(go-dpi)              - Detected only by go-dpi
  BITTORRENT(libprotoident) - Detected only by LPI
  DNS(go-dpi+nDPI)          - Detected by both go-dpi and nDPI
  
In the ClassifyFlow results:
  - Each flow shows which framework detected it FIRST
  - Only one source per protocol

In the ClassifyFlowAll results:
  - Each flow may show multiple frameworks that detected it
  - Multiple sources indicate the protocol was detected by multiple frameworks

PERFORMANCE NOTES:
------------------
- go-dpi is typically fastest (pure Go, minimal overhead)
- LPI offers good balance of speed and accuracy
- nDPI is most comprehensive but slower (C library with more checks)
- ClassifyFlow is faster than ClassifyFlowAll (stops at first match)

================================================================================
                            DETAILED RESULTS
================================================================================
`
	output.WriteString(header)

	type DetectionResult struct {
		Filename        string
		PacketCount     int
		FlowCount       int
		ClassifyFlow    map[types.Protocol]types.ClassificationSource
		ClassifyFlowAll map[types.Protocol][]types.ClassificationSource
	}

	var results []DetectionResult

	files, err := ioutil.ReadDir(dumpsDir)
	if err != nil {
		t.Fatal(err)
	}

	// Process each dump file
	for _, fInfo := range files {
		if fInfo.IsDir() {
			continue
		}

		// Skip non-PCAP files (like .DS_Store, etc.)
		fileName := fInfo.Name()
		if !strings.HasSuffix(fileName, ".pcap") && !strings.HasSuffix(fileName, ".pcapng") && !strings.HasSuffix(fileName, ".cap") {
			continue
		}

		filePath := path.Join(dumpsDir, fileName)
		msg := fmt.Sprintf("\nProcessing: %s", fInfo.Name())
		t.Log(msg)
		output.WriteString(msg + "\n")

		// Flush flow cache for each file to ensure clean state
		types.FlushTrackedFlows()

		result := DetectionResult{
			Filename:        fInfo.Name(),
			ClassifyFlow:    make(map[types.Protocol]types.ClassificationSource),
			ClassifyFlowAll: make(map[types.Protocol][]types.ClassificationSource),
		}

		dumpPackets, err := utils.ReadDumpFile(filePath)
		if err != nil {
			msg := fmt.Sprintf("  Error reading file: %v", err)
			t.Log(msg)
			output.WriteString(msg + "\n")
			continue
		}

		flowsSeen := make(map[*types.Flow]bool)

		// Process all packets
		for packet := range dumpPackets {
			result.PacketCount++

			// Validate packet has minimum required data
			// GetPacketFlow internally handles packets with invalid flow data
			flow, isNew := GetPacketFlow(packet)

			if isNew && flow != nil {
				flowsSeen[flow] = true
			}
		}

		result.FlowCount = len(flowsSeen)

		// First pass: Test ClassifyFlow (stops at first match)
		for flow := range flowsSeen {
			singleResult := ClassifyFlow(flow)
			if singleResult.Protocol != types.Unknown {
				if _, exists := result.ClassifyFlow[singleResult.Protocol]; !exists {
					result.ClassifyFlow[singleResult.Protocol] = singleResult.Source
				}
			}
		}

		// Reload the file and create fresh flows for ClassifyFlowAllModules test
		types.FlushTrackedFlows()
		dumpPackets2, err := utils.ReadDumpFile(filePath)
		if err != nil {
			msg := fmt.Sprintf("  Error reloading file: %v", err)
			t.Log(msg)
			output.WriteString(msg + "\n")
			continue
		}

		flowsSeen2 := make(map[*types.Flow]bool)
		for packet := range dumpPackets2 {
			// Validate packet has minimum required data
			// GetPacketFlow internally handles packets with invalid flow data
			flow, isNew := GetPacketFlow(packet)
			if isNew && flow != nil {
				flowsSeen2[flow] = true
			}
		}

		// Second pass: Test ClassifyFlowAllModules (runs all modules)
		for flow := range flowsSeen2 {
			allResults := ClassifyFlowAllModules(flow)
			for _, res := range allResults {
				if res.Protocol != types.Unknown {
					result.ClassifyFlowAll[res.Protocol] = append(
						result.ClassifyFlowAll[res.Protocol],
						res.Source,
					)
				}
			}
		}

		results = append(results, result)

		msg = fmt.Sprintf("  Packets: %d, Flows: %d", result.PacketCount, result.FlowCount)
		t.Log(msg)
		output.WriteString(msg + "\n")

		msg = fmt.Sprintf("  ClassifyFlow detected: %v", result.ClassifyFlow)
		t.Log(msg)
		output.WriteString(msg + "\n")

		msg = fmt.Sprintf("  ClassifyFlowAll detected: %v", result.ClassifyFlowAll)
		t.Log(msg)
		output.WriteString(msg + "\n")
	}

	// Print comprehensive detection matrix
	separator := strings.Repeat("=", 100)
	output.WriteString("\n" + separator + "\n")
	output.WriteString("DETECTION MATRIX - Which framework detects which protocols\n")
	output.WriteString(separator + "\n")

	t.Log("\n" + separator)
	t.Log("DETECTION MATRIX - Which framework detects which protocols")
	t.Log(separator)

	// Build a map of all protocols seen
	allProtocols := make(map[types.Protocol]bool)
	for _, result := range results {
		for proto := range result.ClassifyFlow {
			allProtocols[proto] = true
		}
		for proto := range result.ClassifyFlowAll {
			allProtocols[proto] = true
		}
	}

	// Convert to sorted list
	var protocols []types.Protocol
	for proto := range allProtocols {
		protocols = append(protocols, proto)
	}

	tableHeader := fmt.Sprintf("\n%-30s | %-15s | %-50s", "File", "ClassifyFlow", "ClassifyFlowAll (all detections)")
	divider := strings.Repeat("-", 100)

	output.WriteString(tableHeader + "\n")
	output.WriteString(divider + "\n")

	t.Log(tableHeader)
	t.Log(divider)

	for _, result := range results {
		classifyFlowStr := ""
		for proto, source := range result.ClassifyFlow {
			if classifyFlowStr != "" {
				classifyFlowStr += ", "
			}
			classifyFlowStr += fmt.Sprintf("%s(%s)", proto, source)
		}
		if classifyFlowStr == "" {
			classifyFlowStr = "none"
		}

		classifyAllStr := ""
		for proto, sources := range result.ClassifyFlowAll {
			if classifyAllStr != "" {
				classifyAllStr += ", "
			}
			sourcesStr := ""
			for i, source := range sources {
				if i > 0 {
					sourcesStr += "+"
				}
				sourcesStr += string(source)
			}
			classifyAllStr += fmt.Sprintf("%s(%s)", proto, sourcesStr)
		}
		if classifyAllStr == "" {
			classifyAllStr = "none"
		}

		line := fmt.Sprintf("%-30s | %-15s | %s", result.Filename, classifyFlowStr, classifyAllStr)
		output.WriteString(line + "\n")
		t.Log(line)
	}

	// Print module-by-module breakdown
	output.WriteString("\n" + separator + "\n")
	output.WriteString("MODULE DETECTION CAPABILITIES\n")
	output.WriteString(separator + "\n")

	t.Log("\n" + separator)
	t.Log("MODULE DETECTION CAPABILITIES")
	t.Log(separator)

	moduleDetections := make(map[types.ClassificationSource]map[string][]types.Protocol)

	for _, result := range results {
		for proto, sources := range result.ClassifyFlowAll {
			for _, source := range sources {
				if moduleDetections[source] == nil {
					moduleDetections[source] = make(map[string][]types.Protocol)
				}
				moduleDetections[source][result.Filename] = append(
					moduleDetections[source][result.Filename],
					proto,
				)
			}
		}
	}

	for source, fileMap := range moduleDetections {
		moduleLine := fmt.Sprintf("\n%s:", source)
		output.WriteString(moduleLine + "\n")
		t.Log(moduleLine)

		for filename, protos := range fileMap {
			protoStrs := make([]string, len(protos))
			for i, p := range protos {
				protoStrs[i] = string(p)
			}
			detailLine := fmt.Sprintf("  %-30s: %s", filename, strings.Join(protoStrs, ", "))
			output.WriteString(detailLine + "\n")
			t.Log(detailLine)
		}
	}

	output.WriteString("\n" + separator + "\n")
	t.Log("\n" + separator)

	// Add summary footer
	footer := `
================================================================================
                                SUMMARY
================================================================================

UNDERSTANDING THE RESULTS:
--------------------------
• "none" in ClassifyFlow column means no protocol was detected by any framework
• Empty ClassifyFlowAll column means no frameworks could identify the traffic
• Protocol discrepancies between frameworks are expected - each has different
  detection methods and signatures

COMMON PATTERNS:
----------------
• DNS, HTTP, FTP: Usually detected by go-dpi first (fast heuristics)
• Complex protocols: May be detected only by nDPI (comprehensive signatures)
• Encrypted traffic: Often detected by LPI or nDPI (payload inspection)
• New/uncommon protocols: May show as Unknown or generic classifications

USING THIS DATA:
----------------
1. Identify which framework best suits your needs based on protocols detected
2. Compare detection accuracy across frameworks for your traffic patterns
3. Understand when to use ClassifyFlow vs ClassifyFlowAll
4. Optimize performance by enabling only needed frameworks

FRAMEWORK SELECTION GUIDE:
--------------------------
• Need speed? Use go-dpi classifiers only
• Need balance? Enable go-dpi + LPI
• Need comprehensive detection? Enable all three (go-dpi + LPI + nDPI)
• Need debugging? Use ClassifyFlowAll to see what each framework detects

For more information, see the project README.md

Generated: ` + fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05")) + `
================================================================================
`
	output.WriteString(footer)
	t.Log(footer)

	// Write results to file
	err = ioutil.WriteFile(outputFile, []byte(output.String()), 0644)
	if err != nil {
		t.Errorf("Failed to write detection matrix to file: %v", err)
	} else {
		t.Logf("\n✓ Detection matrix saved to: %s", outputFile)
	}
}

func BenchmarkClassifyFlow(b *testing.B) {
	dumpsDir := "./godpi_example/dumps/"
	files, err := ioutil.ReadDir(dumpsDir)
	if err != nil {
		b.Fatal(err)
	}
	Initialize()
	defer Destroy()
	// gather all flows in all files
	for i := 0; i < b.N; i++ {
		for _, fInfo := range files {
			filePath := path.Join(dumpsDir, fInfo.Name())
			dumpPackets, err := utils.ReadDumpFile(filePath)
			if err != nil {
				b.Error(err)
			}
			for p := range dumpPackets {
				flow, _ := GetPacketFlow(p)
				if flow.GetClassificationResult().Protocol == types.Unknown {
					ClassifyFlow(flow)
				}
			}
		}
	}
}
