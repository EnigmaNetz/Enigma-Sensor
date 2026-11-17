//go:build linux || darwin

package api

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// freeDiskBytes reports the bytes available to this process on the volume holding dir.
func freeDiskBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil //nolint:gosec // G115: the block size is positive; field types differ by platform
}
