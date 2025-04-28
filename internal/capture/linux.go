//go:build linux

package capture

// LinuxCaptureManager implements CaptureManager for Linux.
type LinuxCaptureManager struct {
	config   Config
	quitChan chan struct{}
}

// NewLinuxCaptureManager creates a new LinuxCaptureManager.
func NewLinuxCaptureManager(cfg Config) *LinuxCaptureManager {
	return &LinuxCaptureManager{config: cfg, quitChan: make(chan struct{})}
}

func (l *LinuxCaptureManager) Start() error {
	// TODO: Implement Linux Zeek capture loop
	return nil
}

func (l *LinuxCaptureManager) Stop() error {
	// TODO: Implement stop logic
	return nil
}

func (l *LinuxCaptureManager) RotateLogs() error {
	// TODO: Implement log rotation (7-day retention)
	return nil
}
