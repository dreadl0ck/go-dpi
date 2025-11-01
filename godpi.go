// Package godpi provides the main API interface for utilizing the go-dpi library.
package godpi

import (
	"time"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
	"github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
)

var activatedModules []types.Module

// moduleList contains all available modules in priority order.
// Classification tries modules sequentially in this order:
//  1. go-dpi classifiers (fast heuristic-based detection)
//  2. Wrappers (LPI and nDPI, in that order)
var moduleList = []types.Module{
	classifiers.NewClassifierModule(),
	wrappers.NewWrapperModule(),
}
var cacheExpiration = 5 * time.Minute

// Initialize initializes the library and the selected modules.
func Initialize(opts ...Options) (errs []error) {
	// apply all options to all modules
	// check if the option will be applied in appropriate module inside Apply func
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		for _, m := range moduleList {
			opt.Apply(m)
		}
	}
	types.InitCache(cacheExpiration)
	for _, module := range moduleList {
		activated := false
		for _, activeModule := range activatedModules {
			if activeModule == module {
				activated = true
				break
			}
		}
		if !activated {
			err := module.Initialize()
			if err == nil {
				activatedModules = append(activatedModules, module)
			} else {
				errs = append(errs, err)
			}
		}
	}
	return
}

// Destroy frees all allocated resources and deactivates the active modules.
func Destroy() (errs []error) {
	types.DestroyCache()
	newActivatedModules := make([]types.Module, 0)
	for _, module := range activatedModules {
		err := module.Destroy()
		if err != nil {
			newActivatedModules = append(newActivatedModules, module)
			errs = append(errs, err)
		}
	}
	activatedModules = newActivatedModules
	return
}

// SetModules selects the modules to be used by the library and their priority order.
// Modules are tried sequentially in the order provided, with the first successful
// classification being returned.
//
// Recommended order for optimal performance:
//  1. go-dpi classifiers (fast heuristic-based)
//  2. libprotoident/LPI (lightweight)
//  3. nDPI (comprehensive but slower)
//
// After calling this method, Initialize should be called, in order to
// initialize any new modules. If Initialize has already been called before,
// Destroy should be called as well before Initialize.
func SetModules(modules []types.Module) {
	moduleList = make([]types.Module, len(modules))
	copy(moduleList, modules)
}

// SetCacheExpiration sets how long after being inactive flows should be
// discarded from the flow tracker. If a negative value is passed, flows
// will never expire. By default, this value is 5 minutes.
// After calling this method, Initialize should be called, in order to
// initialize the cache. If Initialize has already been called before,
// Destroy should be called as well before Initialize.
func SetCacheExpiration(expiration time.Duration) {
	cacheExpiration = expiration
}

// GetPacketFlow returns a Flow for the given packet. If another packet has
// been processed before that was part of the same communication flow, the same
// Flow will be returned, with the new packet added. Otherwise, a new Flow
// will be created with only this packet.
// The function also returns whether the returned Flow is a new one, and not
// one that already existed.
func GetPacketFlow(packet gopacket.Packet) (*types.Flow, bool) {
	return types.GetFlowForPacket(packet)
}

// ClassifyFlow takes a Flow and tries to classify it with all of the activated
// modules sequentially in priority order, until one of them successfully classifies it.
// It returns the detected protocol as well as the source that made the classification.
// If no classification is made, the protocol Unknown is returned.
//
// Module Priority Order (first match wins):
//  1. go-dpi classifiers (fast heuristic-based detection)
//  2. libprotoident/LPI (lightweight payload inspection)
//  3. nDPI (deep packet inspection)
//
// This priority order is maintained regardless of which modules are enabled.
// Each module internally runs its classifiers deterministically to ensure
// reproducible results across multiple runs.
//
// Caching: Once a flow is successfully classified, the result is cached in the
// flow object. Subsequent calls to ClassifyFlow on the same flow will return
// the cached result immediately without re-running any classification modules.
// This ensures optimal performance when processing multiple packets from the
// same flow.
func ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	if len(activatedModules) == 0 {
		return
	}

	// Return cached result if already classified
	if result = flow.GetClassificationResult(); result.Protocol != types.Unknown {
		return result
	}

	// Return Unknown immediately for flows with less than minimum packets
	if flow.GetPacketCount() < types.MinPacketsForClassification {
		return
	}

	// Try each module sequentially in priority order until one succeeds
	for _, module := range activatedModules {
		result = module.ClassifyFlow(flow)
		if result.Protocol != types.Unknown {
			return result
		}
	}

	return
}

// ClassifyFlowAllModules takes a Flow and tries to classify it with all of the
// activated modules sequentially in priority order. Unlike ClassifyFlow, this
// function runs all modules and returns all their classification results.
//
// The modules are executed in the same priority order as ClassifyFlow:
//  1. go-dpi classifiers
//  2. libprotoident/LPI
//  3. nDPI
//
// Results are deduplicated by protocol - if multiple modules detect the same
// protocol, only the first detection (from the higher priority module) is included
// in the results.
//
// This function is useful for debugging, analysis, or when you want to see what
// multiple detection engines report for the same flow.
func ClassifyFlowAllModules(flow *types.Flow) (results []types.ClassificationResult) {
	if len(activatedModules) == 0 {
		return
	}

	// Return cached result if already classified
	if result := flow.GetClassificationResult(); result.Protocol != types.Unknown {
		return []types.ClassificationResult{result}
	}

	// Return empty results immediately for flows with less than minimum packets
	if flow.GetPacketCount() < types.MinPacketsForClassification {
		return
	}

	// Track which protocols we've already detected for deduplication
	seenProtocols := make(map[types.Protocol]bool)

	// Try each module sequentially in priority order
	for _, module := range activatedModules {
		resultsTmp := module.ClassifyFlowAll(flow)

		// Add results, deduplicating by protocol
		for _, resultTmp := range resultsTmp {
			if resultTmp.Protocol != types.Unknown && !seenProtocols[resultTmp.Protocol] {
				seenProtocols[resultTmp.Protocol] = true
				results = append(results, resultTmp)
			}
		}
	}

	return
}
