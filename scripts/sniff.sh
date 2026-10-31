#!/usr/bin/env bash
#
# Capture live device traffic with mitmdump into data/raw/<name>.flow (default name: capture).
# Default mode is a WireGuard tunnel: switch on the tunnel in the WireGuard app on the phone.
#   --qr     print the tunnel config as a QR code (first-time setup, or after the Mac's IP changed)
#   --proxy  use the classic HTTP proxy on port 8080 instead (set it in the phone's Wi-Fi settings)
# Any other args go to mitmdump. Terminal output is quiet by default (request lines and warnings only);
# pass --set termlog_verbosity=info to see connect, disconnect and DNS lines again.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME=capture
if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
  NAME="$1"
  shift
fi
OUT="$REPO_ROOT/data/raw/$NAME.flow"
TLS_LOG="$REPO_ROOT/data/raw/$NAME.tls-failures.txt"
GRPC_LOG="$REPO_ROOT/data/raw/$NAME.grpc.jsonl"
IP="$(ipconfig getifaddr en0 2>/dev/null || echo '<this machine>')"

MODE=wireguard
SHOW_QR=0
PASSTHROUGH=()
QUIET=(--set termlog_verbosity=warn)
for arg in "$@"; do
  case "$arg" in
    --proxy) MODE=regular ;;
    --qr) SHOW_QR=1 ;;
    *termlog_verbosity=*) QUIET=(); PASSTHROUGH+=("$arg") ;;
    *) PASSTHROUGH+=("$arg") ;;
  esac
done

if [ "$MODE" = wireguard ]; then
  if [ "$SHOW_QR" = 1 ] || [ ! -f "$HOME/.mitmproxy/wireguard.conf" ]; then
    uv run --project "$REPO_ROOT" python -m sniff.wgqr || true
  fi
  echo "wireguard: $IP:51820 (switch the tunnel on in the WireGuard app; Wi-Fi HTTP proxy off)"
else
  echo "proxy: $IP:8080 (set as the phone's Wi-Fi HTTP proxy)"
fi

mkdir -p "$(dirname "$OUT")"
rm -f "$TLS_LOG" "$GRPC_LOG"
echo "writing capture to $OUT"
echo "TLS handshake failures (cert pinning) logged to $TLS_LOG"
echo "gRPC messages logged to $GRPC_LOG"
exec env SNIFF_TLS_LOG="$TLS_LOG" SNIFF_GRPC_LOG="$GRPC_LOG" uv run --project "$REPO_ROOT" mitmdump \
  -w "$OUT" -s "$REPO_ROOT/src/sniff/tlslog.py" -s "$REPO_ROOT/src/sniff/grpclog.py" \
  --mode "$MODE" "${QUIET[@]+"${QUIET[@]}"}" ${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}
