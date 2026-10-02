#!/usr/bin/env bash
#
# Extract matching flows from a mitmproxy capture into clean JSON.
# Defaults: data/raw/capture.flow -> data/processed/flows.json, filtered by hosts.txt.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec uv run --project "$REPO_ROOT" sniff-extract "$@"
