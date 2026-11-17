//go:build windows

package api

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// freeDiskBytes reports the bytes available to this process on the volume holding dir.
func freeDiskBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, fmt.Errorf("invalid path %s: %w", dir, err)
	}
	var avail uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, nil, nil); err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", dir, err)
	}
	return avail, nil
}
