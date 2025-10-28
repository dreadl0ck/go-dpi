//go:build linux

package wrappers

// #include "wrappers_config.h"
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"time"
)

// setTimeval sets the timeval structure fields in a platform-specific way.
// On Linux, tv_usec is typically a long or suseconds_t.
func setTimeval(ts *C.struct_timeval, timestamp time.Time) {
	ts.tv_sec = C.long(timestamp.Unix())
	ts.tv_usec = C.long(timestamp.Nanosecond() / 1000)
}
