//go:build !nolpi

package wrappers

// #cgo pkg-config: libprotoident libtrace
import "C"

const HasLPISupport = true
