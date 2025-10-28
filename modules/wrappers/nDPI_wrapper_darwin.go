//go:build darwin

package wrappers

// #include "wrappers_config.h"
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"time"
)

// setTimeval sets the timeval structure fields in a platform-specific way.
// On Darwin/macOS, tv_usec is __darwin_suseconds_t.
func setTimeval(ts *C.struct_timeval, timestamp time.Time) {
	ts.tv_sec = C.long(timestamp.Unix())
	ts.tv_usec = C.__darwin_suseconds_t(timestamp.Nanosecond() / 1000)
}
