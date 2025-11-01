// Package types contains the basic types used by the library.
package types

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/patrickmn/go-cache"
)

// FlowTracker manages flow tracking with thread-safe access to the cache.
type FlowTracker struct {
	Cache *cache.Cache
	mtx   sync.Mutex
}

// FlowTrackerInstance is the global flow tracker instance used by the library.
var FlowTrackerInstance *FlowTracker

// ClassificationSource is the module of the library that is responsible for
// the classification of a flow.
type ClassificationSource string

// ClassificationResult contains the detected protocol and the source of
// the classification from a classification attempt.
type ClassificationResult struct {
	Protocol Protocol
	Class    Category
	Source   ClassificationSource
}

func (result ClassificationResult) String() string {
	return fmt.Sprintf("Detected protocol %v from source %v", result.Protocol, result.Source)
}

// NoSource is returned if no classification was made.
const NoSource = ""

const (
	// MaxPacketsPerFlow is the maximum number of packets to store per flow.
	// This aligns with nDPI's behavior of analyzing only the first 10 TCP packets.
	MaxPacketsPerFlow = 10

	// MinPacketsForClassification is the minimum number of packets required
	// before attempting to classify a flow.
	MinPacketsForClassification = 1
)

// Flow contains sufficient information to classify a flow.
type Flow struct {
	packets        []gopacket.Packet
	numPackets     int
	classification ClassificationResult
	mtx            sync.RWMutex
}

// NewFlow creates an empty flow.
func NewFlow() (flow *Flow) {
	flow = new(Flow)
	flow.packets = make([]gopacket.Packet, 0)
	return
}

// CreateFlowFromPacket creates a flow with a single packet.
func CreateFlowFromPacket(packet gopacket.Packet) (flow *Flow) {
	flow = NewFlow()
	flow.AddPacket(packet)
	return
}

// AddPacket adds a new packet to the flow.
// Stores the exact packet provided without copying.
func (flow *Flow) AddPacket(packet gopacket.Packet) {
	flow.mtx.Lock()
	defer flow.mtx.Unlock()

	// Only store packets up to MaxPacketsPerFlow
	if flow.numPackets < MaxPacketsPerFlow {
		flow.packets = append(flow.packets, packet)
		flow.numPackets++
	}
}

// GetDirection returns the direction of the packet relative to the first packet in the flow.
// Returns 0 if the packet is in the same direction as the first packet, 1 if in the opposite direction.
// Returns 0 if the flow has no packets or if network layer information is unavailable.
func (flow *Flow) GetDirection(packet gopacket.Packet) int {
	flow.mtx.Lock()
	defer flow.mtx.Unlock()

	// Check if flow has any packets to avoid panic
	if len(flow.packets) == 0 {
		return 0
	}

	p := flow.packets[0]
	if nlFirstPacket, nlCurrPacket := p.NetworkLayer(), packet.NetworkLayer(); nlFirstPacket != nil && nlCurrPacket != nil {
		if nlFirstPacket.NetworkFlow().Src() == nlCurrPacket.NetworkFlow().Src() {
			return 0
		} else {
			return 1
		}
	}
	return 0
}

// GetPackets returns the list of packets in a thread-safe way.
func (flow *Flow) GetPackets() (packets []gopacket.Packet) {
	flow.mtx.RLock()
	packets = make([]gopacket.Packet, len(flow.packets))
	copy(packets, flow.packets)
	flow.mtx.RUnlock()
	return
}

// GetPacketCount returns the number of packets seen for this flow.
func (flow *Flow) GetPacketCount() int {
	flow.mtx.RLock()
	count := flow.numPackets
	flow.mtx.RUnlock()
	return count
}

// SetClassificationResult sets the detected protocol and classification source
// for this flow.
func (flow *Flow) SetClassificationResult(protocol Protocol, source ClassificationSource) {
	flow.mtx.Lock()
	flow.classification = ClassificationResult{Protocol: protocol, Source: source}
	flow.mtx.Unlock()
}

// GetClassificationResult returns the currently detected protocol for this
// flow and the source of that detection.
func (flow *Flow) GetClassificationResult() (result ClassificationResult) {
	flow.mtx.RLock()
	result = flow.classification
	flow.mtx.RUnlock()
	return
}

// endpointStrFromFlows creates a string that identifies a flow from the
// network and transport flows of a packet.
// Returns empty string if the flow endpoints are invalid.
func endpointStrFromFlows(networkFlow, transportFlow gopacket.Flow) string {
	// Validate that flows have valid data
	if networkFlow.EndpointType() == 0 || transportFlow.EndpointType() == 0 {
		return ""
	}

	srcEp, dstEp := transportFlow.Endpoints()

	// Verify endpoints have valid data (non-zero length)
	if len(srcEp.Raw()) == 0 || len(dstEp.Raw()) == 0 {
		return ""
	}

	// require a consistent ordering between the endpoints so that packets
	// that go in either direction in the flow will map to the same element
	// in the flowTracker map
	if dstEp.LessThan(srcEp) {
		networkFlow = networkFlow.Reverse()
		transportFlow = transportFlow.Reverse()
	}
	gpktIp1, gpktIp2 := networkFlow.Endpoints()
	gpktPort1, gpktPort2 := transportFlow.Endpoints()
	return fmt.Sprintf("%s:%s,%s:%s", gpktIp1, gpktPort1.String(), gpktIp2, gpktPort2.String())
}

// GetFlowForPacket finds any previous flow that the packet belongs to. It adds
// the packet to that flow and returns the flow.
// If no such flow is found, a new one is created.
func GetFlowForPacket(packet gopacket.Packet) (flow *Flow, isNew bool) {
	isNew = true
	network := packet.NetworkLayer()
	transport := packet.TransportLayer()
	if network != nil && transport != nil {
		gpktNetworkFlow := network.NetworkFlow()
		gpktTransportFlow := transport.TransportFlow()
		flowStr := endpointStrFromFlows(gpktNetworkFlow, gpktTransportFlow)

		// If flowStr is empty, the packet has invalid flow data - fall back to creating a flow
		if flowStr == "" {
			flow = CreateFlowFromPacket(packet)
			return
		}

		// Lock is necessary for the compound check-then-act operation
		// to prevent race conditions when multiple goroutines process
		// packets from the same flow simultaneously
		FlowTrackerInstance.mtx.Lock()
		trackedFlow, ok := FlowTrackerInstance.Cache.Get(flowStr)
		if ok {
			flow = trackedFlow.(*Flow)
			isNew = false
		} else {
			flow = NewFlow()
		}
		FlowTrackerInstance.Cache.Set(flowStr, flow, cache.DefaultExpiration)
		FlowTrackerInstance.mtx.Unlock()
		flow.AddPacket(packet)
	} else {
		flow = CreateFlowFromPacket(packet)
	}
	return
}

// FlushTrackedFlows flushes the map used for tracking flows. Any new packets
// that arrive after this operation will be considered new flows.
func FlushTrackedFlows() {
	FlowTrackerInstance.Cache.Flush()
}

// InitCache initializes the flow cache. It must be called before the cache
// is utilised. Flows will be discarded if they are inactive for the given
// duration. If that value is negative, flows will never expire.
func InitCache(expirationTime time.Duration) {
	FlowTrackerInstance = &FlowTracker{
		Cache: cache.New(expirationTime, 5*time.Minute),
	}
}

// DestroyCache frees the resources used by the flow cache.
func DestroyCache() {
	if FlowTrackerInstance != nil {
		FlowTrackerInstance.Cache.Flush()
		FlowTrackerInstance = nil
	}
}
