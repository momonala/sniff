#!/usr/bin/env bash
#
# Run mitmdump to capture live traffic, writing to data/raw/capture.flow.
# Point the device's HTTP proxy at this machine (port 8080) and trust mitmproxy's CA on-device first.
# Pass a name as the first arg to write data/raw/<name>.flow instead; any further args go to mitmdump.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${1:-capture}"
[ $# -gt 0 ] && shift
OUT="$REPO_ROOT/data/raw/$NAME.flow"

mkdir -p "$(dirname "$OUT")"

echo "writing capture to $OUT"
echo "proxy: $(ipconfig getifaddr en0 2>/dev/null || echo '<this machine>'):8080"
exec uv run --project "$REPO_ROOT" mitmdump -w "$OUT" "$@"
