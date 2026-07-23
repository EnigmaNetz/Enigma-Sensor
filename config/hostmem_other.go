//go:build !linux

package config

// hostAvailableMemoryMB reports host memory as unknown on non-Linux platforms,
// preserving the historical default worker count there.
func hostAvailableMemoryMB() (uint64, bool) {
	return 0, false
}
