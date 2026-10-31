"""Print the WireGuard client config for mitmproxy's wireguard mode as a terminal QR code.

Scan it with the WireGuard iOS app (Add a tunnel -> Create from QR code). The keys
live in ~/.mitmproxy/wireguard.conf and are reused across runs, so this is a one-time import.
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import qrcode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEYS_FILE = Path.home() / ".mitmproxy" / "wireguard.conf"
PORT = 51820


def _public_key(private_b64: str) -> str:
    private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _local_ip() -> str:
    result = subprocess.run(["ipconfig", "getifaddr", "en0"], check=False, capture_output=True, text=True)
    return result.stdout.strip()


def client_config(keys: dict[str, str], host: str) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {keys['client_key']}\n"
        "Address = 10.0.0.1/32\n"
        "DNS = 10.0.0.53\n\n"
        "[Peer]\n"
        f"PublicKey = {_public_key(keys['server_key'])}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {host}:{PORT}\n"
    )


def main() -> None:
    if not KEYS_FILE.exists():
        sys.exit(f"{KEYS_FILE} missing; run ./scripts/sniff.sh once to create it, then re-run with --qr")
    host = _local_ip()
    if not host:
        sys.exit("no IPv4 address on en0; join Wi-Fi (or change the interface in wgqr._local_ip) and retry")
    config = client_config(json.loads(KEYS_FILE.read_text()), host)
    qr = qrcode.QRCode(border=1)
    qr.add_data(config)
    qr.print_ascii(invert=True)


if __name__ == "__main__":
    main()
