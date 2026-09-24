// Command coveragesummary renders a Go coverage profile as a Markdown summary
// for $GITHUB_STEP_SUMMARY. Report-only (B1CF-2014): always exits 0.
//
// Module = first directory under the repo root, or the first two for the
// container dirs internal/, cmd/ and pkg/ (e.g. internal/capture). Lines % is
// covered statements / statements, the same basis as `go tool cover -func`.
// It lives under .github/ so `go test ./...` and `go vet ./...` skip it.
//
// Usage: go run ./.github/scripts/coveragesummary coverage.out
package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

type counts struct {
	covered, total int
	pkgs           map[string]bool
}

func main() {
	profile := "coverage.out"
	if len(os.Args) > 1 {
		profile = os.Args[1]
	}
	fmt.Print(render(profile))
}

func render(profile string) string {
	const heading = "### Unit coverage (report-only)\n\n"
	f, err := os.Open(profile)
	if err != nil {
		return heading + fmt.Sprintf("_%s not found; no coverage data._\n", profile)
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
		return heading + fmt.Sprintf("_Could not read %s: %v_\n", profile, err)
	}

	prefix := modulePath() + "/"
	var total counts
	modules := map[string]*counts{}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		pkg := strings.TrimPrefix(path.Dir(file), prefix)
		if pkg == strings.TrimSuffix(prefix, "/") {
			pkg = "(root)"
		}
		name := moduleOf(pkg)
		m := modules[name]
		if m == nil {
			m = &counts{pkgs: map[string]bool{}}
			modules[name] = m
		}
		m.pkgs[pkg] = true
		m.total += b.stmts
		total.total += b.stmts
		if b.hits > 0 {
			m.covered += b.stmts
			total.covered += b.stmts
		}
	}

	var sb strings.Builder
	sb.WriteString(heading)
	sb.WriteString("| Metric | % | Covered / Total |\n| --- | ---: | ---: |\n")
	fmt.Fprintf(&sb, "| Lines (statements) | %s | %d / %d |\n", pct(total.covered, total.total), total.covered, total.total)
	sb.WriteString("\n#### By module\n\n| Module | Lines % | Packages |\n| --- | ---: | ---: |\n")
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := modules[name]
		fmt.Fprintf(&sb, "| `%s` | %s | %d |\n", name, pct(m.covered, m.total), len(m.pkgs))
	}
	return sb.String()
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
