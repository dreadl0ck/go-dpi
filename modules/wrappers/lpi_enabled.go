//go:build !nolpi

package wrappers

// #cgo CPPFLAGS: -I/usr/local/include -I/opt/homebrew/include
// #cgo LDFLAGS: -L/usr/local/lib -L/opt/homebrew/lib -lprotoident -ltrace
import "C"

const HasLPISupport = true
