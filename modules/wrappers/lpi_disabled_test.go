//go:build nolpi

package wrappers

import "testing"

func TestNoLPIWorker(t *testing.T) {
	if HasLPISupport || NewLPIWrapper().InitializeWrapper() != errorLibraryDisabled {
		t.Fatal("libprotoident must be compiled out")
	}
	w, err := NewIncrementalWorker(true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.lpi || w.lpiEngine != nil || w.engine == nil {
		t.Fatal("expected only an nDPI context")
	}
}
