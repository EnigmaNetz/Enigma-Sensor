package collect_logs

import (
	"EnigmaNetz/Enigma-Go-Sensor/internal/version"
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// CollectLogs creates a zip archive with logs, captures, config, version, and system info for diagnostics.
// zipName is the output file name (e.g., "enigma-logs-YYYYMMDD-HHMMSS.zip").
func CollectLogs(zipName string) error {
	zipFile, err := os.Create(zipName)
	if err != nil {
		return fmt.Errorf("failed to create zip: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add all files in logs/
	logDir := "logs"
	logFiles, err := os.ReadDir(logDir)
	if err == nil { // logs/ may not exist
		for _, entry := range logFiles {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(logDir, entry.Name())
			if err := addFileToZip(zipWriter, path); err != nil {
				// Non-fatal, just skip
			}
		}
	}

	// Recursively add all files in captures/
	capturesDir := "captures"
	_ = addDirToZip(zipWriter, capturesDir) // Non-fatal

	// Add config.json if present
	if _, err := os.Stat("config.json"); err == nil {
		_ = addFileToZip(zipWriter, "config.json") // Non-fatal
	}

	// Add version.txt
	_ = addStringToZip(zipWriter, "version.txt", version.Version+"\n")

	// Add system-info.txt
	sysInfo := getSystemInfo()
	_ = addStringToZip(zipWriter, "system-info.txt", sysInfo)

	return nil
}

func addFileToZip(zipWriter *zip.Writer, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	w, err := zipWriter.Create(filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, file)
	return err
}

func addStringToZip(zipWriter *zip.Writer, filename, content string) error {
	w, err := zipWriter.Create(filename)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(content))
	return err
}

func addDirToZip(zipWriter *zip.Writer, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return addFileToZip(zipWriter, path)
	})
}

func getSystemInfo() string {
	var b strings.Builder
	b.WriteString("OS: ")
	b.WriteString(runtime.GOOS)
	b.WriteString("\nArch: ")
	b.WriteString(runtime.GOARCH)
	b.WriteString("\nGo version: ")
	b.WriteString(runtime.Version())
	b.WriteString("\nNumCPU: ")
	b.WriteString(fmt.Sprintf("%d", runtime.NumCPU()))
	b.WriteString("\nGOMAXPROCS: ")
	b.WriteString(fmt.Sprintf("%d", runtime.GOMAXPROCS(0)))
	b.WriteString("\n")
	// Hostname
	if hn, err := os.Hostname(); err == nil {
		b.WriteString("Hostname: ")
		b.WriteString(hn)
		b.WriteString("\n")
	}
	// Memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b.WriteString(fmt.Sprintf("Memory: Alloc=%d TotalAlloc=%d Sys=%d NumGC=%d\n", m.Alloc, m.TotalAlloc, m.Sys, m.NumGC))

	// OS-specific details
	switch runtime.GOOS {
	case "linux":
		// /etc/os-release
		if f, err := os.Open("/etc/os-release"); err == nil {
			defer f.Close()
			b.WriteString("/etc/os-release:\n")
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "NAME=") || strings.HasPrefix(line, "VERSION=") || strings.HasPrefix(line, "PRETTY_NAME=") {
					b.WriteString("  " + line + "\n")
				}
			}
		}
		// Kernel version
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			b.WriteString("Kernel: " + strings.TrimSpace(string(out)) + "\n")
		}
	case "darwin":
		// sw_vers
		if out, err := exec.Command("sw_vers").Output(); err == nil {
			b.WriteString("sw_vers:\n")
			b.WriteString(string(out))
		}
		// Kernel version
		if out, err := exec.Command("uname", "-r").Output(); err == nil {
			b.WriteString("Kernel: " + strings.TrimSpace(string(out)) + "\n")
		}
	case "windows":
		// Try to read registry for accurate Windows version
		regInfo := getWindowsRegistryVersion()
		if regInfo != "" {
			b.WriteString(regInfo)
		} else if out, err := exec.Command("cmd", "/C", "ver").Output(); err == nil {
			b.WriteString("ver: " + strings.TrimSpace(string(out)) + "\n")
		}
	}
	return b.String()
}

// getWindowsRegistryVersion is a stub here; actual implementation should be in a _windows.go file.
func getWindowsRegistryVersion() string {
	return ""
}
