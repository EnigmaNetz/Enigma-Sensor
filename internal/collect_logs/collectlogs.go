package collect_logs

import (
	"EnigmaNetz/Enigma-Go-Sensor/internal/version"
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// archiveBlob is generated content to be added to the archive under Name.
type archiveBlob struct {
	Name    string
	Content string
}

// archiveFile is one on-disk file to add to the archive. Source is the path
// read from disk; Name is the path recorded inside the archive. Decoupling the
// two keeps archive member names stable (logs/<basename>, captures/<rel>,
// config.json) regardless of whether the source is a packaged absolute path or
// a cwd-relative dev path.
type archiveFile struct {
	Source string
	Name   string
}

// minArchiveBytes is the floor below which a written archive is treated as
// hollow rather than valid.
const minArchiveBytes = 256

// Packaged-install source locations, defaulted from the platform consts. They
// are package vars so tests can point them at temp paths; they default to the
// real absolute install paths written by the installer.
var (
	installLogDir     = defaultInstallLogDir
	installCaptureDir = defaultInstallCaptureDir
	installConfigPath = defaultInstallConfigPath
)

// resolveDir returns installDir if it is an existing directory, else fallback.
func resolveDir(installDir, fallback string) string {
	if info, err := os.Stat(installDir); err == nil && info.IsDir() {
		return installDir
	}
	return fallback
}

// resolveFile returns installPath if it is an existing regular file, else
// fallback.
func resolveFile(installPath, fallback string) string {
	if info, err := os.Stat(installPath); err == nil && info.Mode().IsRegular() {
		return installPath
	}
	return fallback
}

// writeArchive is the platform-specific archive writer. It is a variable so
// tests can substitute a failing or degenerate implementation.
var writeArchive = writeArchiveDefault

// CollectLogs creates an archive with logs, captures, config, version, and system info for diagnostics.
// outName is the output file name (e.g., "enigma-logs-YYYYMMDD-HHMMSS" + ArchiveExt).
// It returns the size of the written archive in bytes. Reporting the result to
// the operator is the caller's job.
func CollectLogs(outName string) (size int64, retErr error) {
	// A failed run must not leave a partial or hollow archive behind for an
	// operator to pick up and ship to support.
	defer func() {
		if retErr != nil {
			_ = os.Remove(outName)
		}
	}()

	// files holds the on-disk source path plus the stable archive member name
	// for each file to add to the archive.
	var files []archiveFile
	var blobs []archiveBlob

	// logBytes and captureBytes count runtime diagnostic content; configBytes
	// counts configuration. They are tracked separately so a bundle carrying
	// only config (no runtime logs/captures) can be rejected as degraded. The
	// generated version.txt and system-info.txt blobs are deliberately excluded
	// from all three: they are always present and would mask an empty bundle.
	var logBytes, captureBytes, configBytes int64

	// Resolve each source to its packaged install location when present, else
	// the cwd-relative dev/source fallback.
	logDir := resolveDir(installLogDir, "logs")
	captureDir := resolveDir(installCaptureDir, "captures")
	configPath := resolveFile(installConfigPath, "config.json")

	// Add all regular files directly in the resolved log dir, under logs/<name>.
	if logFiles, err := os.ReadDir(logDir); err == nil { // log dir may not exist
		for _, entry := range logFiles {
			if entry.IsDir() {
				continue
			}
			if info, err := entry.Info(); err == nil {
				logBytes += info.Size()
			}
			files = append(files, archiveFile{
				Source: filepath.Join(logDir, entry.Name()),
				Name:   "logs/" + entry.Name(),
			})
		}
	}

	// Recursively add all files under the resolved capture dir, under
	// captures/<relative-path> (non-fatal if absent).
	_ = filepath.WalkDir(captureDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			captureBytes += info.Size()
		}
		rel, err := filepath.Rel(captureDir, path)
		if err != nil {
			rel = filepath.Base(path)
		}
		files = append(files, archiveFile{
			Source: path,
			Name:   "captures/" + filepath.ToSlash(rel),
		})
		return nil
	})

	// Add the resolved config file if present, under config.json.
	if info, err := os.Stat(configPath); err == nil {
		configBytes += info.Size()
		files = append(files, archiveFile{Source: configPath, Name: "config.json"})
	}

	runtimeBytes := logBytes + captureBytes

	if runtimeBytes == 0 && configBytes == 0 {
		wd, wdErr := os.Getwd()
		if wdErr != nil {
			wd = "the current working directory"
		}
		return 0, fmt.Errorf("no diagnostic content found in %s: logs/ and captures/ are empty or absent and config.json is missing; run collect-logs from the sensor's working directory (the one holding logs/, captures/, and config.json)", wd)
	}

	if runtimeBytes == 0 {
		// Config was found but there are no runtime diagnostics. A config-only
		// bundle looks complete to support while carrying nothing actionable.
		return 0, fmt.Errorf("degraded bundle: would contain only config and no runtime diagnostics; both the logs dir (%s) and captures dir (%s) are empty or absent, so there are no logs or captures to collect", logDir, captureDir)
	}

	blobs = append(blobs,
		archiveBlob{Name: "version.txt", Content: version.Version + "\n"},
		archiveBlob{Name: "system-info.txt", Content: getSystemInfo()},
	)

	written, err := writeArchive(outName, files, blobs)
	if err != nil {
		return 0, fmt.Errorf("failed to write archive %s: %w", outName, err)
	}

	// gatheredBytes is measured from stat before archiving, so it does not
	// prove anything actually landed in the bundle: every gathered file can
	// still fail to open (root-owned logs/ collected as a non-root user). The
	// count of entries genuinely written is the guard that catches that.
	if len(files) > 0 && written == 0 {
		return 0, fmt.Errorf("archive %s contains no diagnostic files: all %d gathered files failed to be archived (check permissions on logs/, captures/, and config.json)", outName, len(files))
	}

	info, err := os.Stat(outName)
	if err != nil {
		return 0, fmt.Errorf("failed to stat archive %s after writing: %w", outName, err)
	}

	if info.Size() < minArchiveBytes {
		return 0, fmt.Errorf("archive %s is implausibly small: %d bytes", outName, info.Size())
	}

	return info.Size(), nil
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
