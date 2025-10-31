package godpi

import (
	"testing"

	"github.com/dreadl0ck/go-dpi/modules/classifiers"
	"github.com/dreadl0ck/go-dpi/modules/wrappers"
)

func TestLPISupportedCategoriesAndProtocols(t *testing.T) {
	wrapper := wrappers.NewLPIWrapper()

	categories := wrapper.GetSupportedCategories()
	protocols := wrapper.GetSupportedProtocols()

	t.Logf("LPI supports %d categories", len(categories))
	t.Logf("LPI supports %d protocols", len(protocols))

	if len(categories) == 0 {
		t.Error("LPI should support at least one category")
	}

	if len(protocols) == 0 {
		t.Error("LPI should support at least one protocol")
	}
}

func TestNDPISupportedProtocols(t *testing.T) {
	wrapper := wrappers.NewNDPIWrapper()

	protocols := wrapper.GetSupportedProtocols()

	t.Logf("nDPI supports %d protocols", len(protocols))

	if len(protocols) == 0 {
		t.Error("nDPI should support at least one protocol")
	}
}

func TestClassifiersSupportedProtocols(t *testing.T) {
	module := classifiers.NewClassifierModule()

	protocols := module.GetSupportedProtocols()

	t.Logf("Go classifiers support %d protocols", len(protocols))

	if len(protocols) == 0 {
		t.Error("Go classifiers should support at least one protocol")
	}
}
