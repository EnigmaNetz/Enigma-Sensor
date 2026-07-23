//go:build !linux

package selfmetrics

// readRSSAndThreads reports the unavailable sentinels on non-Linux platforms.
func readRSSAndThreads() (uint64, int) {
	return 0, -1
}

// countOpenFDs reports the unavailable sentinel on non-Linux platforms.
func countOpenFDs() int {
	return -1
}
