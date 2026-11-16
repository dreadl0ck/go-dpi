//go:build nolpi

package wrappers

// #cgo CPPFLAGS: -DDISABLE_LPI
import "C"

const HasLPISupport = false
