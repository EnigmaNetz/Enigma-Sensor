package collect_logs

import (
	"EnigmaNetz/Enigma-Go-Sensor/config"
	"EnigmaNetz/Enigma-Go-Sensor/internal/version"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

// archiveEntry is an on-disk file to add to the archive under Name.
type archiveEntry struct {
	Name string
	Path string
	// Redact masks the API key in the file's content. Nil copies it unchanged.
	Redact *redactor
}

// sources is where collect-logs looks for diagnostic content.
type sources struct {
	// configPaths is the sensor's config lookup order.
	configPaths []string
	// baseDirs are the directories a relative path resolves against, in order:
	// the working directory, then the executable's directory, which is the
	// Windows service's working directory.
	baseDirs []string
	// serviceLogDir holds the service manager's console log, if the platform
	// has one.
	serviceLogDir string
	// installLogDir and installCaptureDir are where the platform's installer
	// points the sensor. They are the fallback when the config does not say
	// (it is missing or does not parse) and the relative defaults do not exist.
	installLogDir     string
	installCaptureDir string
}

// Default paths used when no config is found or it does not set them.
const (
	defaultLogDir     = "logs"
	defaultCaptureDir = "captures"
)

// minArchiveBytes is the floor below which a written archive is treated as
// hollow rather than valid.
const minArchiveBytes = 256

// writeArchive is the platform-specific archive writer. It is a variable so
// tests can substitute a failing or degenerate implementation.
var writeArchive = writeArchiveDefault

// CollectLogs creates an archive with the sensor's config, logs, captures,
// version, and system info for diagnostics. The API key is masked in the config
// and logs. outName is the output file name (e.g., "enigma-logs-YYYYMMDD-HHMMSS"
// + ArchiveExt). It returns the size of the written archive in bytes. Reporting
// the result to the operator is the caller's job.
func CollectLogs(outName string) (int64, error) {
	return collect(outName, defaultSources())
}

func defaultSources() sources {
	src := sources{configPaths: config.Paths(runtime.GOOS)}
	if wd, err := os.Getwd(); err == nil {
		src.baseDirs = append(src.baseDirs, wd)
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		src.baseDirs = append(src.baseDirs, filepath.Dir(exe))
	}
	switch runtime.GOOS {
	case "windows":
		// The Windows installer keeps config.example.json's relative paths,
		// which already resolve against the executable's directory.
		src.serviceLogDir = `C:\ProgramData\EnigmaSensor\logs`
	case "linux":
		// Matches the config installer/install-enigma-sensor.sh writes.
		src.installLogDir = "/var/log/enigma-sensor"
		src.installCaptureDir = "/var/lib/enigma-sensor/captures"
	}
	return src
}

func collect(outName string, src sources) (size int64, retErr error) {
	// Never overwrite or follow an existing file: the archive is created
	// exclusively, and a failed run must not delete what was already there.
	if _, err := os.Lstat(outName); err == nil {
		return 0, fmt.Errorf("%s already exists", outName)
	}
	// A failed run must not leave a partial or hollow archive behind for an
	// operator to pick up and ship to support.
	defer func() {
		// An ErrExist means another process created outName after the check
		// above; that file is not this run's to delete.
		if retErr != nil && !errors.Is(retErr, fs.ErrExist) {
			_ = os.Remove(outName)
		}
	}()

	g := &gatherer{seen: map[string]bool{}}
	logDir, logPrefix, captureDir := defaultLogDir, "", defaultCaptureDir
	logFromConfig, captureFromConfig := false, false
	red := newRedactor()
	var configBlob *archiveBlob

	var notes strings.Builder
	configPath, err := config.FindPath(src.resolveAll(src.configPaths))
	if err != nil {
		fmt.Fprintf(&notes, "config: none found (tried %s)\n", strings.Join(src.configPaths, ", "))
	} else {
		fmt.Fprintf(&notes, "config: %s\n", configPath)
		data, readErr := os.ReadFile(configPath)
		if readErr != nil {
			fmt.Fprintf(&notes, "config not archived: %v\n", readErr)
		}
		cfg, keys := readConfigLoosely(data)
		red = newRedactor(keys...)
		if readErr == nil {
			if masked, ok := redactConfig(data); ok {
				configBlob = &archiveBlob{Name: "config.json", Content: string(masked)}
				g.gatheredBytes += int64(len(masked))
			} else {
				fmt.Fprintf(&notes, "config not archived: it is not valid JSON, so its secrets cannot be located\n")
			}
		}
		// Validation does not change the log or capture paths, so the loosely
		// parsed config says where the sensor writes even when it is refused.
		_, loadErr := config.LoadConfig(configPath)
		if loadErr != nil {
			fmt.Fprintf(&notes, "config load error: %v\n", loadErr)
		}
		if cfg.Logging.File != "" {
			logDir = filepath.Dir(cfg.Logging.File)
			logPrefix = strings.TrimSuffix(filepath.Base(cfg.Logging.File), filepath.Ext(cfg.Logging.File))
			logFromConfig = true
		} else if loadErr == nil {
			// A valid config without logging.file logs to stdout only.
			logDir = ""
		}
		if cfg.Capture.OutputDir != "" {
			captureDir = cfg.Capture.OutputDir
			captureFromConfig = true
		}
	}

	if logDir != "" {
		dir := src.resolve(logDir)
		if !logFromConfig {
			dir = orInstallDir(dir, src.installLogDir)
		}
		fmt.Fprintf(&notes, "logs: %s\n", dir)
		g.addDir(dir, "logs", logPrefix, red)
	}
	if src.serviceLogDir != "" {
		fmt.Fprintf(&notes, "service logs: %s\n", src.serviceLogDir)
		g.addDir(src.serviceLogDir, "service-logs", "", red)
	}
	dir := src.resolve(captureDir)
	if !captureFromConfig {
		dir = orInstallDir(dir, src.installCaptureDir)
	}
	fmt.Fprintf(&notes, "captures: %s\n", dir)
	g.addTree(dir, "captures")

	// gatheredBytes counts only real diagnostic content gathered from disk.
	// The generated blobs are deliberately excluded: they are always present
	// and would mask an otherwise empty bundle.
	if g.gatheredBytes == 0 {
		return 0, fmt.Errorf("no diagnostic content found: no config file, logs, or captures.\n%sRun collect-logs as the user the sensor runs as (root or Administrator), or from the sensor's working directory", notes.String())
	}

	var blobs []archiveBlob
	if configBlob != nil {
		blobs = append(blobs, *configBlob)
	}
	blobs = append(blobs,
		archiveBlob{Name: "version.txt", Content: version.Version + "\n"},
		archiveBlob{Name: "system-info.txt", Content: getSystemInfo()},
		archiveBlob{Name: "collect-logs.txt", Content: notes.String()},
	)

	written, err := writeArchive(outName, g.entries, blobs)
	if err != nil {
		return 0, fmt.Errorf("failed to write archive %s: %w", outName, err)
	}

	// gatheredBytes is measured from stat before archiving, so it does not
	// prove anything actually landed in the bundle: every gathered file can
	// still fail to open (root-owned logs collected as a non-root user). The
	// count of entries genuinely written is the guard that catches that.
	if len(g.entries) > 0 && written == 0 {
		return 0, fmt.Errorf("archive %s contains no diagnostic files: all %d gathered files failed to be archived (run collect-logs as the user the sensor runs as)", outName, len(g.entries))
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

// resolve returns path unchanged if it is absolute, otherwise joined to the
// first base directory where it exists, or to the first base directory.
func (s sources) resolve(path string) string {
	if filepath.IsAbs(path) || len(s.baseDirs) == 0 {
		return path
	}
	for _, base := range s.baseDirs {
		candidate := filepath.Join(base, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join(s.baseDirs[0], path)
}

// orInstallDir returns dir if it exists, otherwise installDir if that is set.
func orInstallDir(dir, installDir string) string {
	if _, err := os.Stat(dir); err == nil || installDir == "" {
		return dir
	}
	return installDir
}

// resolveAll expands each relative path against every base directory, keeping
// the lookup order.
func (s sources) resolveAll(paths []string) []string {
	var out []string
	for _, path := range paths {
		if filepath.IsAbs(path) || len(s.baseDirs) == 0 {
			out = append(out, path)
			continue
		}
		for _, base := range s.baseDirs {
			out = append(out, filepath.Join(base, path))
		}
	}
	return out
}

// readConfigLoosely parses config content without validating it, since an
// invalid config still needs its key masked and its paths followed. Content
// that does not parse gives an empty config. It returns the config and every
// API key to mask in logs: the parsed key, any api_key value found in the raw
// content, and a SENSOR_ENIGMA_API_API_KEY override.
func readConfigLoosely(data []byte) (config.Config, []string) {
	var cfg config.Config
	_ = json.Unmarshal(data, &cfg)
	keys := append(apiKeysIn(data), cfg.EnigmaAPI.APIKey)
	_ = config.ApplyEnvOverrides(&cfg)
	return cfg, append(keys, cfg.EnigmaAPI.APIKey)
}

// gatherer collects archive entries, skipping files it already has.
type gatherer struct {
	entries       []archiveEntry
	seen          map[string]bool
	gatheredBytes int64
}

func (g *gatherer) add(e archiveEntry) {
	key := e.Path
	if abs, err := filepath.Abs(e.Path); err == nil {
		key = abs
	}
	if g.seen[key] {
		return
	}
	info, err := os.Stat(e.Path)
	if err != nil {
		return
	}
	g.seen[key] = true
	g.gatheredBytes += info.Size()
	if e.Redact != nil && isGzip(e.Name) {
		// Redacted content is archived decompressed.
		e.Name = e.Name[:len(e.Name)-len(".gz")]
	}
	g.entries = append(g.entries, e)
}

// addDir adds the regular files directly in dir whose names start with prefix.
// The prefix matches a log file's rotated backups (enigma-sensor-<time>.log.gz)
// without picking up unrelated files that share its directory.
func (g *gatherer) addDir(dir, archiveDir, prefix string, red *redactor) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		g.add(archiveEntry{
			Name:   archiveDir + "/" + entry.Name(),
			Path:   filepath.Join(dir, entry.Name()),
			Redact: red,
		})
	}
}

// addTree adds every file under dir unchanged. dir itself may be a symlink,
// since it comes from the config, but symlinks inside it are skipped: they
// could point at files, such as the config, that must not be archived unmasked.
func (g *gatherer) addTree(dir, archiveDir string) {
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		g.add(archiveEntry{Name: archiveDir + "/" + filepath.ToSlash(rel), Path: path})
		return nil
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
