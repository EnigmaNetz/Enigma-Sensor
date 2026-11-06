# Copied from Enigma-Release .github/actions/ci-gates/scripts/gates.py at 8287083. This repo is public and
# that one is private, so it cannot call the shared action. go-test.yml runs the coverage gate only.
"""PR gates for the shared license, IaC, and coverage templates (B1CF-2165).

Each gate compares the PR head with its base, so findings that already exist on the base branch
never fail a PR; only what the PR adds does.

    license   Trivy license JSON (head, base) + license-dispositions.yml. Fails on a forbidden or
              restricted (package, license) pair that is new in head and has no `accept`
              disposition. Uses the weekly health report's rule engine, so the PR check and the
              report agree on what a disposition covers.
    iac       Trivy config JSON (head, base). Fails on a critical or high misconfiguration that is
              new in head, or on a new inline trivy:ignore or tfsec:ignore comment, which would
              hide a finding with no waiver record. Findings are keyed by check ID, file and
              resource, not line, so moving code within a file does not make an old finding new.
    coverage  Cobertura XML reports + the repo's floor file. Fails when line coverage is below the
              floor, when the PR lowers or removes any floor (the ratchet only moves up), or when a report
              names no file in the repo, because diff-cover would then pass with nothing to
              measure. The 80% on changed lines check is diff-cover, run by the action itself.

The license gate has two passes. --precheck needs no credentials and sets needs-dispositions; the
gate itself runs only when that says so. Most PRs add no license, so most runs never mint an App
token, and Dependabot runs (which get no Actions secrets) pass.

Every gate prints a Markdown summary (also appended to $GITHUB_STEP_SUMMARY) and exits 1 on failure.
The coverage gate uses only the standard library, so a public repo that cannot call this private
action (Enigma-Sensor) can copy this file into its own workflow.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

GATED_LICENSE_CATEGORIES = ("forbidden", "restricted")
GATED_IAC_SEVERITIES = ("CRITICAL", "HIGH")
HEADROOM = 1.0  # points a floor sits below measured, so an ordinary PR doesn't trip the ratchet
INLINE_IGNORE = re.compile(r"(trivy|tfsec):ignore", re.IGNORECASE)
IAC_SUFFIXES = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json")


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh) or {}


def _output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def _summary(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    print(text)
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(text)


# ---------------------------------------------------------------- license

def license_findings(report: dict) -> dict[tuple[str, str], dict]:
    """Forbidden/restricted app-dependency licenses, keyed by (package, license)."""
    found: dict[tuple[str, str], dict] = {}
    for result in report.get("Results") or []:
        for lic in result.get("Licenses") or []:
            cat = (lic.get("Category") or "").lower()
            if cat not in GATED_LICENSE_CATEGORIES:
                continue
            pkg = lic.get("PkgName") or ""
            if not pkg:
                # Loose license files (Class license-file) have no package to disposition.
                continue
            name = lic.get("Name") or "(none)"
            found.setdefault((pkg, name), {"os": False, "package": pkg, "license": name, "category": cat})
    return found


def new_licenses(head: dict, base: dict) -> tuple[list[dict], int]:
    head_f, base_f = license_findings(head), license_findings(base)
    return [f for k, f in sorted(head_f.items()) if k not in base_f], len(base_f)


def license_precheck(head: dict, base: dict) -> tuple[bool, list[str]]:
    """Whether the PR adds a gated license, so the dispositions must be read. Needs no credentials."""
    new, existing = new_licenses(head, base)
    lines = ["### License check"]
    if not new:
        return False, lines + [f"No new forbidden or restricted licenses ({existing} on the base branch are not re-checked)."]
    lines += [f"- new: `{f['package']}` ({f['license']}, {f['category']})" for f in new]
    return True, lines + ["", "Checking these against the license dispositions."]


def license_gate(head: dict, base: dict, dispositions: dict) -> tuple[bool, list[str]]:
    # The rule engine lives with the health report in this repo (health-report/report). A composite
    # action is downloaded as the whole repo at the pinned ref, so the path is stable. Imported
    # here so the coverage gate needs nothing outside this file.
    sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "health-report"))
    from report.licenses import match

    new, existing = new_licenses(head, base)
    blocked, accepted = [], []
    for f in new:
        rule = match(f, dispositions)
        if rule and rule.get("disposition") == "accept":
            accepted.append((f, rule))
        else:
            blocked.append((f, rule))
    lines = ["### License check"]
    if not new:
        lines.append(f"No new forbidden or restricted licenses ({existing} on the base branch are not re-checked).")
    for f, rule in accepted:
        lines.append(f"- accepted: `{f['package']}` ({f['license']}, {f['category']}) by disposition `{rule['id']}`")
    for f, rule in blocked:
        why = f"disposition `{rule['id']}` says {rule['disposition']}" if rule else "no disposition"
        lines.append(f"- **blocked**: `{f['package']}` ({f['license']}, {f['category']}): {why}")
    if blocked:
        lines += ["", "Replace the dependency, or add a reviewed disposition to "
                  "Enigma-Infrastructure `health-reports/license-dispositions.yml` and re-run."]
    return not blocked, lines


# ---------------------------------------------------------------- iac

def iac_findings(report: dict) -> dict[tuple[str, str, str], dict]:
    """Failed critical/high misconfigurations keyed by (check ID, file, resource)."""
    found: dict[tuple[str, str, str], dict] = {}
    for result in report.get("Results") or []:
        target = result.get("Target") or ""
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL" or (m.get("Severity") or "").upper() not in GATED_IAC_SEVERITIES:
                continue
            resource = (m.get("CauseMetadata") or {}).get("Resource") or ""
            key = (m.get("ID") or m.get("AVDID") or "?", target, resource)
            found.setdefault(key, {"id": key[0], "target": target, "resource": resource,
                                   "severity": m.get("Severity"), "title": m.get("Title") or ""})
    return found


def inline_ignores(root: str) -> Counter:
    """Inline ignore comments under a checkout, as (relative path, line text) counts."""
    found: Counter = Counter()
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", ".terraform", "node_modules")]
        for name in files:
            if name.endswith(IAC_SUFFIXES) or name.startswith("Dockerfile"):
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    found.update((os.path.relpath(path, root), line.strip()) for line in fh if INLINE_IGNORE.search(line))
    return found


def iac_gate(head: dict, base: dict, added_ignores: list[tuple[str, str]] = ()) -> tuple[bool, list[str]]:
    head_f, base_f = iac_findings(head), iac_findings(base)
    new = [f for k, f in sorted(head_f.items()) if k not in base_f]
    lines = ["### IaC check"]
    for path, text in added_ignores:
        lines.append(f"- **inline ignore added** in {path}: `{text}`")
    if added_ignores:
        lines += ["", "Remove it. An accepted risk goes in the repo's `.trivyignore.yaml`, with a statement and `expired_at`.", ""]
    if not new:
        lines.append(f"No new critical or high misconfigurations ({len(base_f)} existing on the base branch are not re-checked).")
    for f in new:
        where = f"{f['target']}" + (f" `{f['resource']}`" if f["resource"] else "")
        lines.append(f"- **{f['severity']}** {f['id']} in {where}: {f['title']}")
    if new:
        lines += ["", "Fix the finding, or record an accepted risk in the repo's `.trivyignore.yaml` "
                  "(`misconfigurations:` with a statement and `expired_at`) and re-run."]
    return not new and not added_ignores, lines


# ---------------------------------------------------------------- coverage

def line_coverage(paths: list[str]) -> float:
    """Line coverage percent across Cobertura reports (summed lines, not averaged rates).

    Uses the report's own totals. Counting <line> elements instead is wrong: Cobertura repeats
    each line under <methods>, so those lines count twice.
    """
    covered = valid = 0
    for p in paths:
        root = ET.parse(p).getroot()
        if root.get("lines-valid") is None or root.get("lines-covered") is None:
            raise ValueError(f"{p} has no lines-covered and lines-valid totals; is it a Cobertura report?")
        covered += int(root.get("lines-covered"))
        valid += int(root.get("lines-valid"))
    if valid == 0:
        raise ValueError(f"no measurable lines in {paths}")
    return 100.0 * covered / valid


def read_floors(text: str | None) -> dict[str, float]:
    """Floors by suite. Raises ValueError on anything but percentages: json.loads accepts NaN, and
    every comparison with NaN is false, which would turn the ratchet off."""
    if not text:
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("the floor file must be a JSON object of suite names to percentages")
    for suite, value in data.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 100:
            raise ValueError(f"the floor for {suite!r} must be a number from 0 to 100, not {value!r}")
    return {suite: float(value) for suite, value in data.items()}


def base_floors(floor_file: str, base_sha: str) -> dict[str, float]:
    """The floors on the base commit, empty if the file is not there (a repo's first floor).

    A base commit that cannot be read raises instead: in a shallow clone it would otherwise look
    like "no floor yet", and a PR could lower a floor unnoticed.
    """
    listed = subprocess.run(["git", "ls-tree", "--name-only", base_sha, "--", floor_file], capture_output=True, text=True)
    if listed.returncode != 0:
        raise ValueError(f"cannot read base commit {base_sha}; check out with fetch-depth: 0")
    if not listed.stdout.strip():
        return {}
    shown = subprocess.run(["git", "show", f"{base_sha}:{floor_file}"], capture_output=True, text=True)
    if shown.returncode != 0:
        raise ValueError(f"cannot read {floor_file} at {base_sha}")
    return read_floors(shown.stdout)


def lowered_floors(head: dict[str, float], base: dict[str, float]) -> list[str]:
    """Every base floor that head lowers or removes, across all suites: checking only the suite
    in hand would let a PR rename a suite to drop its floor."""
    out = [f"`{s}` removed (was {v:.1f}%)" for s, v in base.items() if s not in head]
    return out + [f"`{s}` from {v:.1f}% to {head[s]:.1f}%" for s, v in base.items() if s in head and head[s] + 1e-9 < v]


def tracked_files() -> set[str]:
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True, check=True).stdout
    return set(filter(None, out.split("\0")))


def report_resolves(path: str, tracked: set[str], root: str) -> bool:
    """Whether any file in a Cobertura report is a file in this repo. Mirrors diff-cover's matching
    (it has no API for this): a class's filename, alone or joined to each <source>, equals a
    relative or absolute repo path.

    diff-cover exits 0 with "No lines with coverage information" when none match, so without this
    a report with the wrong path prefix looks exactly like a PR that changed no code. One matching
    file is enough, so a report that is only partly wrong still passes this check.
    """
    doc = ET.parse(path).getroot()
    sources = [s.text.strip() for s in doc.findall("sources/source") if s.text]
    known = tracked | {os.path.join(root, t) for t in tracked}
    for clazz in doc.iter("class"):
        name = (clazz.get("filename") or "").replace("\\", "/")
        if name and (name in known or any(os.path.join(src, name) in known for src in sources)):
            return True
    return False


def coverage_gate(measured: float, floor: float | None, lowered: list[str], suite: str,
                  floor_file: str) -> tuple[bool, list[str]]:
    ok = True
    lines = [f"### Coverage ratchet: {suite}", f"Line coverage: **{measured:.2f}%**"]
    if floor is None:
        return False, lines + [f"**No floor** for `{suite}` in `{floor_file}`. Add one at the current level."]
    lines.append(f"Floor: {floor:.1f}%")
    if measured + 1e-9 < floor:
        ok = False
        lines.append(f"**Below the floor** by {floor - measured:.2f} points. Add tests, do not lower the floor.")
    if lowered:
        ok = False
        lines.append(f"**Floor lowered** against the base branch: {'; '.join(lowered)}. The ratchet only moves up.")
    # Floors sit HEADROOM below measured on purpose, so only speak up once there is more than that.
    target = math.floor(measured * 10) / 10 - HEADROOM
    if ok and target > floor + 1e-9:
        lines.append(f"Coverage has risen; raise `{suite}` in `{floor_file}` to {target:.1f} in this PR.")
    return ok, lines


# ---------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="gate", required=True)
    lic = sub.add_parser("license")
    lic.add_argument("--head", required=True)
    lic.add_argument("--base", required=True)
    lic.add_argument("--precheck", action="store_true", help="only report whether the dispositions need reading")
    lic.add_argument("--dispositions", help="required unless --precheck")
    iac = sub.add_parser("iac")
    iac.add_argument("--head", required=True)
    iac.add_argument("--base", required=True)
    iac.add_argument("--head-dir", required=True, help="PR head checkout")
    iac.add_argument("--base-dir", required=True, help="PR base checkout")
    cov = sub.add_parser("coverage")
    cov.add_argument("--reports", required=True, help="glob of Cobertura XML files for this suite")
    cov.add_argument("--extra-reports", default="", help="glob of reports that count toward changed lines only")
    cov.add_argument("--floor-file", required=True)
    cov.add_argument("--suite", required=True)
    cov.add_argument("--base-sha", required=True, help="PR base commit; the ratchet reads the old floor from it")
    a = ap.parse_args(argv)
    # Checked here, not by argparse alone: an empty value from CI must fail, not skip the check.
    if a.gate == "license" and bool(a.precheck) == bool(a.dispositions):
        ap.error("license needs exactly one of --precheck and --dispositions")
    if a.gate == "coverage" and not a.base_sha:
        ap.error("--base-sha must not be empty")

    if a.gate == "license":
        if a.precheck:
            needed, lines = license_precheck(_load_json(a.head), _load_json(a.base))
            _output("needs-dispositions", "true" if needed else "false")
            _summary(lines)
            return 0
        import yaml  # license only; see the module docstring

        with open(a.dispositions, encoding="utf-8") as fh:
            disp = yaml.safe_load(fh) or {}
        ok, lines = license_gate(_load_json(a.head), _load_json(a.base), disp)
    elif a.gate == "iac":
        added = sorted((inline_ignores(a.head_dir) - inline_ignores(a.base_dir)).elements())
        ok, lines = iac_gate(_load_json(a.head), _load_json(a.base), added)
    else:
        heading = f"### Coverage ratchet: {a.suite}"
        paths = [p for p in sorted(glob.glob(a.reports, recursive=True)) if os.path.isfile(p)]
        extra = [p for p in sorted(glob.glob(a.extra_reports, recursive=True)) if os.path.isfile(p)] if a.extra_reports else []
        if not paths or (a.extra_reports and not extra):
            _summary([heading, f"**No coverage reports** matched `{a.reports if not paths else a.extra_reports}`."])
            return 1
        floor_text = Path(a.floor_file).read_text(encoding="utf-8") if Path(a.floor_file).is_file() else None
        try:
            tracked, root = tracked_files(), os.getcwd()
            unresolved = [p for p in paths + extra if not report_resolves(p, tracked, root)]
            if unresolved:
                _summary([heading, f"**No file in the repo matches** {', '.join(f'`{p}`' for p in unresolved)}. "
                          "Report paths must be relative to the repo root; check the report's `<source>` and `filename` values."])
                return 1
            floors = read_floors(floor_text)
            lowered = lowered_floors(floors, base_floors(a.floor_file, a.base_sha))
            measured = line_coverage(paths)
        except (ValueError, ET.ParseError) as e:
            _summary([heading, f"**Invalid coverage data**: {e}"])
            return 1
        ok, lines = coverage_gate(measured, floors.get(a.suite), lowered, a.suite, a.floor_file)
    _summary(lines)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
