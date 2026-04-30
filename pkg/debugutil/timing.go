package debugutil

import "os"

// TimingEnabled controls verbose timing diagnostics.
// It is disabled by default and enabled only when CADSCANNER_DEBUG_TIMING=1.
func TimingEnabled() bool {
	return os.Getenv("CADSCANNER_DEBUG_TIMING") == "1"
}
