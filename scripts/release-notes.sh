#!/bin/bash
# Prints release notes for <tag>: the PRs merged since <previous tag>, then one
# `Update: <level>` line set to the highest update:* label among them.
#
# Usage: scripts/release-notes.sh <previous-tag|""> <tag>
#
# An empty <previous-tag> lists every PR reachable from <tag>. PRs come from the
# merge commits in the range, so a PR merged weeks before the tag still counts.
# A PR with no update:* label (merged before the label check existed) counts as
# optional. Needs git and an authenticated gh with read access to the repo's PRs.
#
# Every git and gh call runs as its own command, so set -e stops the script on
# any failure instead of printing an empty list and `Update: optional`.
set -euo pipefail

[ $# -eq 2 ] || { echo "Usage: $0 <previous-tag|\"\"> <tag>" >&2; exit 1; }
PREV="$1"
TAG="$2"

for ref in "$PREV" "$TAG"; do
  [ -z "$ref" ] && continue
  git rev-parse --verify -q "$ref^{commit}" >/dev/null || { echo "Not a commit: $ref" >&2; exit 1; }
done
RANGE="$TAG"
[ -n "$PREV" ] && RANGE="$PREV..$TAG"

# --first-parent keeps to the mainline, so a revert or cherry-pick on a branch
# that repeats a "(#N)" subject does not list that PR twice.
LOG=$(git log --first-parent --format='%H %P%x09%s' "$RANGE")

# Merge commits read "Merge pull request #N from ..."; squash merges end "(#N)".
# A merge whose branch adds nothing beyond <previous tag> is skipped: the
# version-bump PR is tagged on its branch commit, so its merge lands after the
# tag although its content shipped in the previous release.
PRS=()
while IFS=$'\t' read -r shas subject; do
  [ -z "$shas" ] && continue
  read -r _ _ branch _ <<<"$shas"
  if [[ $subject =~ ^Merge\ pull\ request\ \#([0-9]+)\  ]]; then
    n="${BASH_REMATCH[1]}"
    if [ -n "$PREV" ] && [ -n "$branch" ]; then
      new=$(git rev-list --count "$PREV..$branch")
      [ "$new" -eq 0 ] && continue
    fi
    PRS+=("$n")
  elif [[ $subject =~ \(\#([0-9]+)\)$ ]]; then
    PRS+=("${BASH_REMATCH[1]}")
  fi
done <<<"$LOG"

LEVEL=optional
if [ ${#PRS[@]} -eq 0 ]; then
  echo "No pull requests merged since ${PREV:-the first commit}."
else
  SORTED=$(printf '%s\n' "${PRS[@]}" | sort -n -u)
  while read -r n; do
    pr=$(gh pr view "$n" --json number,title,labels)
    title=$(jq -r '.title | gsub("[\r\n]+"; " ")' <<<"$pr")
    labels=$(jq -r '.labels[].name' <<<"$pr")
    echo "- #$n $title"
    if grep -qx 'update:security' <<<"$labels"; then
      LEVEL=security
    elif [ "$LEVEL" = optional ] && grep -qx 'update:recommended' <<<"$labels"; then
      LEVEL=recommended
    fi
  done <<<"$SORTED"
fi

echo
echo "Update: $LEVEL"
