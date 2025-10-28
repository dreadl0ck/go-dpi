package godpi

import (
	"io/ioutil"
	"path"
	"testing"

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

	// Create a flow with enough packets to pass MinPacketsForClassification
	testFlow := types.NewFlow()
	// Read packets from test file to create a realistic flow
	dumpPackets, err := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	// Add at least MinPacketsForClassification packets
	for i := 0; i < 10; i++ {
		packet := <-dumpPackets
		if packet == nil {
			break
		}
		testFlow.AddPacket(packet)
	}

	result := ClassifyFlow(testFlow)
	// With concurrent execution, all modules run simultaneously
	// so we just check that a successful classification was made
	if result.Protocol != types.HTTP {
		t.Errorf("Expected HTTP protocol, got protocol %v from source %v", result.Protocol, result.Source)
	}
	if result.Source != "module2" && result.Source != "module3" {
		t.Errorf("Expected result from module2 or module3, got source %v", result.Source)
	}

	// Create another flow with enough packets for ClassifyFlowAllModules
	testFlow2 := types.NewFlow()
	dumpPackets2, err := utils.ReadDumpFile("./godpi_example/dumps/http.cap")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		packet := <-dumpPackets2
		if packet == nil {
			break
		}
		testFlow2.AddPacket(packet)
	}

	results := ClassifyFlowAllModules(testFlow2)
	// With concurrent execution, we should get results from both successful modules,
	// but order is non-deterministic
	if len(results) != 2 {
		t.Errorf("Expected 2 results from ClassifyFlowAllModules, got %d", len(results))
	}
	for _, res := range results {
		if res.Protocol != types.HTTP {
			t.Errorf("Expected HTTP protocol in results, got %v", res.Protocol)
		}
		if res.Source != "module2" && res.Source != "module3" {
			t.Errorf("Expected result from module2 or module3, got source %v", res.Source)
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
