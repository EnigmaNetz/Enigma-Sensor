package load

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"EnigmaNetz/Enigma-Go-Agent/internal/api"
	"EnigmaNetz/Enigma-Go-Agent/internal/capture/common"
	types "EnigmaNetz/Enigma-Go-Agent/internal/processor/common"

	"bufio"
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

// Config controls the synthetic capture duration and traffic generation.
type Config struct {
	Duration   time.Duration // How long to run traffic generation
	RPS        int           // Target requests per second
	Throughput int           // Target network throughput in MB/sec (0 = default 1)
}

// RunSyntheticCaptureLoad generates local HTTP traffic, captures it, processes
// the resulting PCAP, and uploads the generated logs.
func RunSyntheticCaptureLoad(ctx context.Context, cap Capturer, proc Processor, up Uploader, cfg Config) error {
	if cfg.Duration <= 0 {
		cfg.Duration = 5 * time.Second
	}
	if cfg.RPS <= 0 {
		cfg.RPS = 100
	}
	if cfg.Throughput <= 0 {
		cfg.Throughput = 1 // MB/sec
	}
	throughputBytes := cfg.Throughput * 1024 * 1024

	// Find a non-loopback IPv4 address for local client traffic
	localIP := "127.0.0.1"
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				localIP = ipnet.IP.String()
				break
			}
		}
	}

	// Start a simple HTTP server on all interfaces (0.0.0.0)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	srv.Addr = listener.Addr().String()
	log.Printf("[local server] Listening on %s (client will use %s)", listener.Addr().String(), localIP)
	go srv.Serve(listener)
	defer srv.Shutdown(context.Background())

	// Generate traffic for the specified duration.
	genCtx, cancelGen := context.WithTimeout(ctx, cfg.Duration)
	defer cancelGen()
	var wg sync.WaitGroup
	wg.Add(1)
	go func(localAddr string, localIP string) {
		defer wg.Done()
		client := &http.Client{}
		var payloadSize int
		if throughputBytes > 0 && cfg.RPS > 0 {
			payloadSize = throughputBytes / cfg.RPS
			if payloadSize < 1 {
				payloadSize = 1
			}
		} else {
			payloadSize = 1024 // 1KB default
		}
		interval := time.Second / time.Duration(cfg.RPS)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}

		domains := []string{
			"example.com", "google.com", "github.com", "wikipedia.org", "amazon.com",
			"microsoft.com", "apple.com", "cloudflare.com", "reddit.com", "stackoverflow.com",
		}
		for genCtx.Err() == nil {
			payload := make([]byte, payloadSize)
			_, _ = rand.Read(payload)
			// 90% local server, 10% random external domain
			var url string
			if rand.Intn(10) < 9 {
				// Use real IP and actual port
				_, port, _ := net.SplitHostPort(localAddr)
				url = "http://" + localIP + ":" + port + "/test"
			} else {
				domain := domains[rand.Intn(len(domains))]
				url = "http://" + domain + "/test"
			}
			req, _ := http.NewRequestWithContext(genCtx, http.MethodPost, url, bytes.NewReader(payload))
			resp, _ := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(interval)
		}
	}(listener.Addr().String(), localIP)

	// Capture traffic while it is being generated.
	capCfg := common.CaptureConfig{CaptureWindow: cfg.Duration, OutputDir: "./captures"}
	pcapPath, err := cap.Capture(ctx, capCfg)
	if err != nil {
		return err
	}

	wg.Wait()

	result, err := proc.ProcessPCAP(pcapPath)
	if err != nil {
		return err
	}

	// --- Traffic Stats Summary ---
	stats := make(map[string]interface{})
	// PCAP file size
	if fi, err := os.Stat(pcapPath); err == nil {
		stats["pcap_bytes"] = fi.Size()
	}
	// conn.xlsx row count
	connRows := "N/A"
	if n, err := countLogRows(result.ConnPath); err == nil {
		connRows = fmt.Sprintf("%d", n)
	}
	// dns.xlsx row count
	dnsRows := "N/A"
	if n, err := countLogRows(result.DNSPath); err == nil {
		dnsRows = fmt.Sprintf("%d", n)
	}
	fmt.Printf("\n--- Traffic Capture Stats ---\n")
	fmt.Printf("PCAP: %s (%d bytes)\n", pcapPath, stats["pcap_bytes"])
	fmt.Printf("conn.xlsx: %s (%s rows)\n", result.ConnPath, connRows)
	fmt.Printf("dns.xlsx: %s (%s rows)\n", result.DNSPath, dnsRows)
	fmt.Printf("----------------------------\n\n")

	if up != nil {
		if err := up.UploadLogs(ctx, api.LogFiles{DNSPath: result.DNSPath, ConnPath: result.ConnPath}); err != nil {
			return err
		}
		fmt.Println("Upload to API succeeded.")
	}

	return nil
}

// countLogRows returns the number of data rows in a Zeek TSV file (lines not starting with # and not empty).
func countLogRows(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		n++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return n, nil
}
