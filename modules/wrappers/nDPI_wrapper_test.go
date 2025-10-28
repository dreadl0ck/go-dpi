package wrappers

import (
	"strings"
	"testing"

	"unsafe"

	"github.com/dreadl0ck/go-dpi/types"
	"github.com/dreadl0ck/go-dpi/utils"
	"github.com/gopacket/gopacket"
)

func TestNewNDPIWrapper(t *testing.T) {
	if NewNDPIWrapper() == nil {
		t.Error("nDPI wrapper not created")
	}
}

func TestNDPIWrapperClassification(t *testing.T) {
	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	// Add enough packets for proper classification
	for i := 0; i < 10; i++ {
		packet := <-packetChan
		if packet == nil {
			break
		}
		flow.AddPacket(packet)
	}

	wrapper := NewNDPIWrapper()
	switch errCode := wrapper.InitializeWrapper(); errCode {
	case 0:
		defer wrapper.DestroyWrapper()
		result, err := wrapper.ClassifyFlow(flow)
		if err != nil || result.Proto != types.HTTP {
			t.Errorf("Incorrectly detected flow protocol: %v instead of HTTP, error: %v", result, err)
		}
	case errorLibraryDisabled:
		t.Skip("nDPI library is disabled")
	default:
		t.Error("nDPI initialization returned error code:", errCode)
	}

}

func TestNDPIWrapper_InitializeWrapper(t *testing.T) {
	wrapper := NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return 0 },
		},
	}
	// shouldn't be an error if 0 is returned
	if wrapper.InitializeWrapper() != 0 {
		t.Error("Error in wrapper initialization")
	}

	wrapper = NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return 1 },
		},
	}
	// should be an error if nonzero is returned
	if wrapper.InitializeWrapper() == 0 {
		t.Error("Wrapper initialization did not throw error")
	}
}

func TestNDPIWrapper_DestroyWrapper(t *testing.T) {
	destroyCalled := false
	wrapper := NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiDestroy: func() { destroyCalled = true },
		},
	}
	wrapper.DestroyWrapper()
	if !destroyCalled {
		t.Error("Wrapper destroy was not called")
	}
}

func TestNDPIWrapper_ClassifyFlowErrors(t *testing.T) {
	var retVal int32
	timesCalled := 0

	wrapper := &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiPacketProcess: func(_ gopacket.Packet, _ unsafe.Pointer) int32 {
				timesCalled++
				return retVal
			},
			ndpiAllocFlow: func(gopacket.Packet) unsafe.Pointer {
				return nil
			},
			ndpiFreeFlow: func(unsafe.Pointer) {
			},
		},
	}

	// empty flow should be unknown
	if ret, _ := wrapper.ClassifyFlow(types.NewFlow()); ret.Proto != types.Unknown {
		t.Errorf("Incorrectly classified empty flow: %v instead of unknown", ret)
	}

	flow := types.NewFlow()
	packetChan, _ := utils.ReadDumpFile("../../godpi_example/dumps/http.cap")
	packet := <-packetChan
	flow.AddPacket(packet)

	// test nDPI error codes returning errors containing the correct strings
	returnValueErrors := map[int32]string{
		-10:  "IPv6",
		-11:  "fragmented",
		-12:  "flow",
		-100: "unknown",
	}

	for value, errStr := range returnValueErrors {
		retVal = value
		_, err := wrapper.ClassifyFlow(flow)
		if err == nil {
			t.Errorf("Expected error for return value %d, but got nil", value)
			continue
		}
		if !strings.Contains(err.Error(), errStr) {
			t.Errorf("Incorrect error thrown for return value %d: %v", value, err.Error())
		}
	}
}

func TestNDPIWrapper_GetWrapperName(t *testing.T) {
	if name := NewNDPIWrapper().GetWrapperName(); name != NDPIWrapperName {
		t.Error("Wrong wrapper name returned:", name)
	}
}
