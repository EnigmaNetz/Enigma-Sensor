package load

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"
)

// Capturer matches the capture interface used by the main agent.
type Capturer interface {
	Capture(ctx context.Context, cfg common.CaptureConfig) (string, error)
}

// Processor processes a PCAP and produces conn and dns logs.
type Processor interface {
	ProcessPCAP(pcapPath string) (types.ProcessedData, error)
}

// Uploader uploads processed logs to the API.
type Uploader interface {
	UploadLogs(ctx context.Context, files api.LogFiles) error
}

// Config controls the synthetic capture duration and output location.
type Config struct {
	Duration  time.Duration
	OutputDir string
}

// RunSyntheticCaptureLoad generates local HTTP traffic, captures it, processes
// the resulting PCAP, and uploads the generated logs.
func RunSyntheticCaptureLoad(ctx context.Context, cap Capturer, proc Processor, up Uploader, cfg Config) error {
	if cfg.Duration <= 0 {
		cfg.Duration = 5 * time.Second
	}

	// Start a simple HTTP server on a random port.
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv.Addr = listener.Addr().String()
	go srv.Serve(listener)
	defer srv.Shutdown(context.Background())

	// Generate traffic for the specified duration.
	genCtx, cancelGen := context.WithTimeout(ctx, cfg.Duration)
	defer cancelGen()
	var wg sync.WaitGroup
	wg.Add(1)
	go func(addr string) {
		defer wg.Done()
		client := &http.Client{}
		for genCtx.Err() == nil {
			req, _ := http.NewRequestWithContext(genCtx, http.MethodGet, "http://"+addr, nil)
			_, _ = client.Do(req)
			time.Sleep(100 * time.Millisecond)
		}
	}(srv.Addr)

	// Capture traffic while it is being generated.
	capCfg := common.CaptureConfig{CaptureWindow: cfg.Duration, OutputDir: cfg.OutputDir}
	pcapPath, err := cap.Capture(ctx, capCfg)
	if err != nil {
		return err
	}

	wg.Wait()

	result, err := proc.ProcessPCAP(pcapPath)
	if err != nil {
		return err
	}

	if up != nil {
		if err := up.UploadLogs(ctx, api.LogFiles{DNSPath: result.DNSPath, ConnPath: result.ConnPath}); err != nil {
			return err
		}
	}

	return nil
}
