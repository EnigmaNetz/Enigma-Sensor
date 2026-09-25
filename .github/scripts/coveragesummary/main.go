// Command coveragesummary renders a Go coverage profile as a Markdown summary
// for $GITHUB_STEP_SUMMARY. Report-only (B1CF-2014): always exits 0.
//
// Module = first directory under the repo root, or the first two for the
// container dirs internal/, cmd/ and pkg/ (e.g. internal/capture). Lines % is
// covered statements / statements, the same basis as `go tool cover -func`.
// It lives under .github/ so `go test ./...` and `go vet ./...` skip it.
// -json-out also writes coverage-normalized.json (schema_version 1) for
// cross-repo reporting; Go has no branch or function counts, so those are null.
//
// Usage: go run ./.github/scripts/coveragesummary [-json-out path] [-suite unit|integration] coverage.out
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const heading = "### Unit coverage (report-only)\n\n"

type counts struct {
	covered, total int
	pkgs           map[string]bool
	files          map[string]bool
}

type summary struct {
	total   counts
	modules map[string]*counts
}

func main() {
	jsonOut := flag.String("json-out", "", "also write normalized coverage JSON to this path")
	suite := flag.String("suite", "unit", "suite name for the JSON: unit or integration")
	flag.Parse()
	profile := "coverage.out"
	if flag.NArg() > 0 {
		profile = flag.Arg(0)
	}
	s, note := load(profile)
	if s == nil {
		fmt.Print(note)
		return
	}
	fmt.Print(s.markdown())
	if *jsonOut != "" {
		// Problems go to stderr only, so the job summary is never affected.
		if err := writeJSON(s, *jsonOut, *suite); err != nil {
			fmt.Fprintf(os.Stderr, "coveragesummary: not writing %s: %v\n", *jsonOut, err)
		}
	}
}

// load parses the profile; on failure it returns nil and the Markdown note to print.
func load(profile string) (*summary, string) {
	f, err := os.Open(profile)
	if err != nil {
		return nil, heading + fmt.Sprintf("_%s not found; no coverage data._\n", profile)
	}
	defer f.Close()

	// A block can appear once per test binary; count it as covered if any run hit it.
	type block struct{ stmts, hits int }
	blocks := map[string]*block{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// file:startLine.startCol,endLine.endCol numStmts count
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		stmts, err1 := strconv.Atoi(fields[1])
		hits, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		if b, ok := blocks[fields[0]]; ok {
			b.hits += hits
		} else {
			blocks[fields[0]] = &block{stmts, hits}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, heading + fmt.Sprintf("_Could not read %s: %v_\n", profile, err)
	}

	prefix := modulePath() + "/"
	s := &summary{modules: map[string]*counts{}}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		pkg := strings.TrimPrefix(path.Dir(file), prefix)
		if pkg == strings.TrimSuffix(prefix, "/") {
			pkg = "(root)"
		}
		name := moduleOf(pkg)
		m := s.modules[name]
		if m == nil {
			m = &counts{pkgs: map[string]bool{}, files: map[string]bool{}}
			s.modules[name] = m
		}
		m.pkgs[pkg] = true
		m.files[file] = true
		m.total += b.stmts
		s.total.total += b.stmts
		if b.hits > 0 {
			m.covered += b.stmts
			s.total.covered += b.stmts
		}
	}
	return s, ""
}

func (s *summary) names() []string {
	names := make([]string, 0, len(s.modules))
	for name := range s.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *summary) markdown() string {
	total := s.total
	var sb strings.Builder
	sb.WriteString(heading)
	sb.WriteString("| Metric | % | Covered / Total |\n| --- | ---: | ---: |\n")
	fmt.Fprintf(&sb, "| Lines (statements) | %s | %d / %d |\n", pct(total.covered, total.total), total.covered, total.total)
	sb.WriteString("\n#### By module\n\n| Module | Lines % | Packages |\n| --- | ---: | ---: |\n")
	for _, name := range s.names() {
		m := s.modules[name]
		fmt.Fprintf(&sb, "| `%s` | %s | %d |\n", name, pct(m.covered, m.total), len(m.pkgs))
	}
	return sb.String()
}

type metric struct {
	Covered int     `json:"covered"`
	Total   int     `json:"total"`
	Pct     float64 `json:"pct"`
}

type moduleEntry struct {
	Name  string  `json:"name"`
	Files int     `json:"files"`
	Lines *metric `json:"lines"`
}

type normalized struct {
	SchemaVersion int     `json:"schema_version"`
	Repo          string  `json:"repo"`
	Suite         string  `json:"suite"`
	Tool          string  `json:"tool"`
	Commit        *string `json:"commit"`
	Ref           *string `json:"ref"`
	GeneratedAt   string  `json:"generated_at"`
	Totals        struct {
		Lines        *metric  `json:"lines"`
		Statements   *metric  `json:"statements"`
		Branches     *metric  `json:"branches"`
		Functions    *metric  `json:"functions"`
		GateBasisPct *float64 `json:"gate_basis_pct"`
	} `json:"totals"`
	Modules []moduleEntry `json:"modules"`
}

// newMetric rounds pct to 2 decimals and reports 0 when total is 0.
func newMetric(covered, total int) *metric {
	m := &metric{Covered: covered, Total: total}
	if total > 0 {
		m.Pct = math.Round(10000*float64(covered)/float64(total)) / 100
	}
	return m
}

func envOrNil(key string) *string {
	if v := os.Getenv(key); v != "" {
		return &v
	}
	return nil
}

// writeJSON writes the normalized file. Go counts statements (the Markdown's
// "Lines (statements)"), so lines and statements carry the same numbers.
func writeJSON(s *summary, out, suite string) error {
	if suite != "unit" && suite != "integration" {
		return fmt.Errorf("-suite must be unit or integration, got %q", suite)
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		repo = filepath.ToSlash(wd)
	}
	n := normalized{
		SchemaVersion: 1,
		Repo:          path.Base(repo),
		Suite:         suite,
		Tool:          "go",
		Commit:        envOrNil("GITHUB_SHA"),
		Ref:           envOrNil("GITHUB_REF_NAME"),
		GeneratedAt:   time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Modules:       []moduleEntry{},
	}
	n.Totals.Lines = newMetric(s.total.covered, s.total.total)
	n.Totals.Statements = newMetric(s.total.covered, s.total.total)
	for _, name := range s.names() {
		m := s.modules[name]
		n.Modules = append(n.Modules, moduleEntry{Name: name, Files: len(m.files), Lines: newMetric(m.covered, m.total)})
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, append(data, '\n'), 0o644)
}

func moduleOf(pkg string) string {
	parts := strings.Split(pkg, "/")
	switch {
	case len(parts) >= 2 && (parts[0] == "internal" || parts[0] == "cmd" || parts[0] == "pkg"):
		return parts[0] + "/" + parts[1]
	default:
		return parts[0]
	}
}

// modulePath reads the module path from go.mod in the working directory.
func modulePath() string {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

func pct(covered, total int) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(covered)/float64(total))
}
