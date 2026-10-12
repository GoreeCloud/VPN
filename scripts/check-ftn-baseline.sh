#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
test -f README.md || fail "Missing root README"
grep -Fq '# GoreeCloud VPN' README.md || fail "Incorrect product README"
test -f LICENSE || fail "Missing root upstream license"
test -f LICENSES/BSD-3-Clause.txt || fail "Missing BSD license"
test -f LICENSES/AGPL-3.0.txt || fail "Missing AGPL license"
for component in management signal relay combined; do
  test -f "$component/LICENSE" || fail "Missing $component/LICENSE"
done
test -f AUTHORS || fail "Missing upstream attribution"
test -f docs/upstream/NETBIRD_README.md || fail "Missing original upstream README"
test -f docs/fork-to-native/UPSTREAM.md || fail "Missing provenance"
grep -Fq '8c70f9ec71e2a3b4ed01e8776a6a78b1f5a8118c' docs/fork-to-native/UPSTREAM.md || fail "Missing pinned revision"
test -f go.mod || fail "Missing original Go module"
grep -Fxq 'module github.com/netbirdio/netbird' go.mod || fail "Unexpected module rewrite before validation"

# Deny all upstream workflows. Only the independently reviewed baseline workflow is approved.
if test -d .github/workflows; then
  for f in .github/workflows/*; do
    test -f "$f" || continue
    test "$(basename "$f")" = "foundation-check.yml" || fail "Unreviewed workflow: $f"
  done
fi
echo "PASS: provenance, license attribution and initial workflow guardrails."

