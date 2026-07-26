#!/usr/bin/env bash
#
# Version-sync gate.
#
# ~1200 lines including a whole new security gate once shipped under an unchanged
# 0.2.1, so the "stable fallback" Playground link served a build with neither the
# bulk gate nor the session-bound window while the README said both were covered.
# Nothing caught it because nothing compared these files.
#
# Checks that the plugin header, readme.txt's Stable tag, the enqueue version,
# and every version reference in the pinned blueprint all agree.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
note() { printf '  %s\n' "$1"; }

header=$(grep -m1 -E '^\s*\*\s*Version:' consequential-actions.php | sed -E 's/.*Version:[[:space:]]*//' | tr -d '[:space:]')
stable=$(grep -m1 -E '^Stable tag:' readme.txt | sed -E 's/^Stable tag:[[:space:]]*//' | tr -d '[:space:]')
asset=$(grep -m1 -E "^[[:space:]]*'[0-9]+\.[0-9]+\.[0-9]+'," consequential-actions.php | tr -d "[:space:]',")

echo "Plugin header version: ${header}"

if [ "$stable" != "$header" ]; then
	echo "::error ::readme.txt Stable tag (${stable}) does not match the plugin header (${header})"
	fail=1
fi

if [ -n "$asset" ] && [ "$asset" != "$header" ]; then
	echo "::error ::asset enqueue version (${asset}) does not match the plugin header (${header})"
	fail=1
fi

# Every version reference in the pinned blueprint must be the header version.
# This is the one that actually drifted: the pin is only useful if it points at
# a tag containing the code the README describes.
pinned=$(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' demo/blueprint-pinned.json | sort -u || true)
if [ -z "$pinned" ]; then
	echo "::error ::demo/blueprint-pinned.json contains no vX.Y.Z reference — the pin cannot be verified"
	fail=1
else
	while IFS= read -r ref; do
		[ -z "$ref" ] && continue
		if [ "$ref" != "v${header}" ]; then
			echo "::error ::demo/blueprint-pinned.json pins ${ref}, but the plugin header is ${header} — bump the pin with the version"
			note "every plugin/narrator/blueprint URL in that file must reference v${header}"
			fail=1
		fi
	done <<< "$pinned"
fi

if [ "$fail" -ne 0 ]; then
	echo "Version sync FAILED."
	exit 1
fi

echo "Version sync OK: header, Stable tag, asset version, and the pinned blueprint all agree on ${header}."
