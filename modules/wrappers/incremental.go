package wrappers

// #include "incremental.h"
// #include "LPI_wrapper_impl.hpp"
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/dreadl0ck/go-dpi/types"
)

// IncrementalWorker owns a detection context. Calls and its flows must be serialized by its owner.
type IncrementalWorker struct {
	engine    unsafe.Pointer
	lpiEngine unsafe.Pointer
	lpi       bool
}

// IncrementalFlow never retains packet objects. Small unidentified first packets are
// kept as bytes until a second packet justifies retaining the much larger nDPI state.
type IncrementalFlow struct {
	ndpi, lpi         unsafe.Pointer
	ndpiDone, lpiDone bool
	Results           [2]types.ClassificationResult
	Count             int
	firstIP           []byte
	firstMillis       uint64
}

// LPI's registry is shared read-only; initialization and destruction require exclusive access.
var incrementalLPI struct {
	sync.RWMutex
	users int
}

var incrementalNDPI sync.Mutex

// NewIncrementalWorker creates private nDPI and libtrace contexts for the enabled engines.
func NewIncrementalWorker(ndpi, lpi bool) (*IncrementalWorker, error) {
	w := &IncrementalWorker{lpi: lpi}
	if lpi {
		incrementalLPI.Lock()
		if incrementalLPI.users == 0 && C.lpiInitLibrary() != 0 {
			incrementalLPI.Unlock()
			return nil, fmt.Errorf("libprotoident initialization failed")
		}
		incrementalLPI.users++
		w.lpiEngine = C.dpi_lpi_create()
		incrementalLPI.Unlock()
		if w.lpiEngine == nil {
			w.Close()
			return nil, fmt.Errorf("libtrace scratch allocation failed")
		}
	}
	if ndpi {
		incrementalNDPI.Lock()
		w.engine = C.dpi_ndpi_create()
		incrementalNDPI.Unlock()
		if w.engine == nil {
			w.Close()
			return nil, fmt.Errorf("nDPI initialization failed")
		}
	}
	return w, nil
}

// Close releases the contexts after the owner has freed every outstanding flow.
func (w *IncrementalWorker) Close() {
	if w.engine != nil {
		incrementalNDPI.Lock()
		C.dpi_ndpi_destroy(w.engine)
		incrementalNDPI.Unlock()
	}
	w.engine = nil
	if w.lpi {
		incrementalLPI.Lock()
		C.dpi_lpi_destroy(w.lpiEngine)
		w.lpiEngine = nil
		incrementalLPI.users--
		if incrementalLPI.users == 0 {
			C.lpiDestroyLibrary()
		}
		incrementalLPI.Unlock()
		w.lpi = false
	}
}

// Free releases inspection state, preserving results. Discard or zero the flow before reuse.
func (w *IncrementalWorker) Free(f *IncrementalFlow) {
	f.firstIP = nil
	if f.ndpi != nil {
		C.dpi_ndpi_free(f.ndpi)
		f.ndpi = nil
	}
	if f.lpi != nil {
		incrementalLPI.RLock()
		C.dpi_lpi_free(f.lpi)
		incrementalLPI.RUnlock()
		f.lpi = nil
	}
}

// Process advances each enabled engine. A compact first packet is replayed once on promotion.
// ip is the captured network-layer bytes; ethernet is optional for LPI.
func (w *IncrementalWorker) Process(f *IncrementalFlow, ip, ethernet []byte, millis uint64, direction int, final bool) error {
	last := C.int(0)
	if final {
		last = 1
	}
	var err error
	if w.lpi && !f.lpiDone && len(ethernet) > 0 && len(ethernet) <= 65535 {
		terminal := C.int(0)
		if w.engine == nil || f.ndpiDone {
			terminal = 1
		}
		incrementalLPI.RLock()
		r := C.dpi_lpi_step(w.lpiEngine, f.lpi, (*C.uint8_t)(unsafe.Pointer(&ethernet[0])), C.uint16_t(len(ethernet)), C.int(direction), last, terminal)
		incrementalLPI.RUnlock()
		f.lpi = r.flow
		if r.error != 0 {
			err = fmt.Errorf("libprotoident packet: %d", r.error)
		}
		proto := lpiCodeToProtocol[uint32(r.protocol)]
		if r.error == 0 && proto != "" && proto != types.UNKNOWN && proto != types.NO_PAYLOAD {
			index := f.Count
			for i := 0; i < f.Count; i++ {
				if f.Results[i].Source == LPIWrapperName {
					index = i
					break
				}
			}
			if index == f.Count {
				f.Count++
			}
			f.Results[index] = types.ClassificationResult{Protocol: proto, Class: lpiCodeToCategory[uint32(r.category)], Source: LPIWrapperName}
			if f.Count == 2 && f.Results[0].Source == NDPIWrapperName {
				f.Results[0], f.Results[1] = f.Results[1], f.Results[0]
			}
			f.lpiDone = r.flow == nil
		}
	}
	if w.engine != nil && !f.ndpiDone && len(ip) > 0 && len(ip) <= 65535 {
		var r C.dpi_step
		if len(f.firstIP) != 0 {
			r = C.dpi_ndpi_resume(w.engine, (*C.uint8_t)(unsafe.Pointer(&f.firstIP[0])), C.uint16_t(len(f.firstIP)), C.uint64_t(f.firstMillis),
				(*C.uint8_t)(unsafe.Pointer(&ip[0])), C.uint16_t(len(ip)), C.uint64_t(millis), last)
			f.firstIP = nil
		} else {
			compact := f.ndpi == nil && !final && len(ip) <= 512
			finish := last
			if compact {
				finish = 1
			}
			r = C.dpi_ndpi_step(w.engine, f.ndpi, (*C.uint8_t)(unsafe.Pointer(&ip[0])), C.uint16_t(len(ip)), C.uint64_t(millis), finish)
			if compact && r.error == 0 && r.protocol == 0 {
				f.firstIP = append([]byte(nil), ip...)
				f.firstMillis = millis
			}
		}
		f.ndpi = r.flow
		if r.error != 0 {
			err = fmt.Errorf("nDPI packet: %d", r.error)
		}
		proto := ndpiCodeToProtocol[uint32(r.protocol)]
		if r.protocol != 0 {
			f.ndpiDone = true
			if proto != "" && proto != types.Unknown {
				f.Results[f.Count] = types.ClassificationResult{Protocol: proto, Source: NDPIWrapperName}
				f.Count++
			}
		}
	}
	if f.ndpiDone && f.lpi != nil {
		for _, result := range f.Results[:f.Count] {
			if result.Source == LPIWrapperName && result.Protocol != types.UDP {
				incrementalLPI.RLock()
				C.dpi_lpi_free(f.lpi)
				incrementalLPI.RUnlock()
				f.lpi = nil
				f.lpiDone = true
				break
			}
		}
	}
	if final {
		w.Free(f)
		f.ndpiDone = true
		f.lpiDone = true
	}
	return err
}

// Complete reports whether all enabled engines have stopped inspecting the flow.
func (w *IncrementalWorker) Complete(f *IncrementalFlow) bool {
	return (w.engine == nil || f.ndpiDone) && (!w.lpi || f.lpiDone)
}
