// Package classifiers contains the custom classifiers for each protocol
// and the helpers for applying them on a flow.
package classifiers

import (
	"sync"

	"github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
)

// GoDPIName is the name of the library, to be used as an identifier for the
// source of a classification.
const GoDPIName = types.ClassificationSource("go-dpi")

// ClassifierModule is the module that contains the custom go-dpi flow classifiers.
type ClassifierModule struct {
	classifierList []GenericClassifier
}

// GenericClassifier is implemented by every classifier. It contains a method
// that returns the classifier's detected protocol.
type GenericClassifier interface {
	// GetProtocol returns the protocol this classifier can detect.
	GetProtocol() types.Protocol
}

// HeuristicClassifier is implemented by the classifiers that have heuristic
// methods to detect a protocol.
type HeuristicClassifier interface {
	// HeuristicClassify returns whether this classifier can identify the flow
	// using heuristics.
	HeuristicClassify(*types.Flow) bool
}

// ClassifierModuleConfig is given to the module's ConfigureModule method, in
// order to set which classifiers are active and their order.
// The order of classifiers matters: ClassifyFlow will return the first matching
// classifier's result.
type ClassifierModuleConfig struct {
	Classifiers []GenericClassifier
}

// NewClassifierModule returns a new ClassifierModule with the default
// configuration. By default, all classifiers are active.
//
// The order of classifiers in the list defines their priority: when multiple
// classifiers could match the same flow, ClassifyFlow returns the first match.
// This ensures deterministic and reproducible classification results.
func NewClassifierModule() *ClassifierModule {
	module := &ClassifierModule{}
	module.classifierList = []GenericClassifier{
		FTPClassifier{},
		HTTPClassifier{},
		ICMPClassifier{},
		NetBIOSClassifier{},
		DNSClassifier{},
		RDPClassifier{},
		RPCClassifier{},
		SMBClassifier{},
		SMTPClassifier{},
		SSHClassifier{},
		SSLClassifier{},
		JABBERClassifier{},
		MQTTClassifier{},
	}
	return module
}

// Initialize initializes the module instance.
func (module *ClassifierModule) Initialize() error {
	return nil
}

// Destroy destroys the module instance.
func (module *ClassifierModule) Destroy() error {
	return nil
}

// ClassifyFlow applies all the classifiers to a flow sequentially in the order
// they appear in the classifier list, and returns the protocol detected by the
// first matching classifier. If no classifier matches, the returned protocol is Unknown.
//
// This method runs classifiers deterministically (not concurrently) to ensure:
//   - Reproducible results across multiple runs
//   - Predictable behavior when multiple classifiers could match the same flow
//   - Priority-based classification based on classifier order
//
// The classifier order in NewClassifierModule defines the priority when multiple
// protocols could match the same flow.
func (module *ClassifierModule) ClassifyFlow(flow *types.Flow) (result types.ClassificationResult) {
	if len(module.classifierList) == 0 {
		return
	}

	// Run each classifier sequentially in order until one matches
	for _, classifier := range module.classifierList {
		if heuristic, ok := classifier.(HeuristicClassifier); ok {
			if heuristic.HeuristicClassify(flow) {
				result = types.ClassificationResult{
					Protocol: classifier.GetProtocol(),
					Source:   GoDPIName,
				}
				flow.SetClassificationResult(result.Protocol, result.Source)
				return
			}
		}
	}

	// No classifier matched
	return
}

// ClassifyFlowAll applies all the classifiers to a flow concurrently and returns
// all the protocols detected by any of the classifiers.
func (module *ClassifierModule) ClassifyFlowAll(flow *types.Flow) (results []types.ClassificationResult) {
	if len(module.classifierList) == 0 {
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Launch a goroutine for each classifier
	for _, classifier := range module.classifierList {
		if heuristic, ok := classifier.(HeuristicClassifier); ok {
			wg.Add(1)
			go func(h HeuristicClassifier, c GenericClassifier) {
				defer wg.Done()
				if h.HeuristicClassify(flow) {
					res := types.ClassificationResult{
						Protocol: c.GetProtocol(),
						Source:   GoDPIName,
					}
					mu.Lock()
					results = append(results, res)
					mu.Unlock()
				}
			}(heuristic, classifier)
		}
	}

	wg.Wait()
	return
}

// ConfigureModule configures this module instance with the given configuration.
// This should called before the module instance is initialized, otherwise
// Destroy and Initialize should be called on the module manually.
func (module *ClassifierModule) ConfigureModule(config ClassifierModuleConfig) {
	module.classifierList = config.Classifiers
}

// GetSupportedProtocols returns all protocols supported by the go-dpi classifiers.
func (module *ClassifierModule) GetSupportedProtocols() []types.Protocol {
	protocols := make([]types.Protocol, 0, len(module.classifierList))

	for _, classifier := range module.classifierList {
		protocols = append(protocols, classifier.GetProtocol())
	}

	return protocols
}

// checkFlowLayer applies the check function to the specified layer of each
// packet in a flow, where it is available. It returns whether there is a
// packet in the flow for which the check function returns true.
func checkFlowLayer(flow *types.Flow, layerType gopacket.LayerType,
	checkFunc func(layer gopacket.Layer) bool) bool {
	for _, packet := range flow.GetPackets() {
		if layer := packet.Layer(layerType); layer != nil {
			if checkFunc(layer) {
				return true
			}
		}
	}
	return false
}

// checkFirstPayload applies the check function to the payload of the first
// packet that has the specified layer. It returns the result of that function
// on that first packet, or false if no such packet exists.
func checkFirstPayload(packets []gopacket.Packet, layerType gopacket.LayerType,
	checkFunc func(payload []byte, packetsRest []gopacket.Packet) bool) bool {
	for i, packet := range packets {
		if layer := packet.Layer(layerType); layer != nil {
			if payload := layer.LayerPayload(); len(payload) > 0 {
				return checkFunc(payload, packets[i+1:])
			}
		}
	}
	return false
}
