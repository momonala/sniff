"""mitmproxy addon: record TLS handshake failures (certificate pinning evidence).

Pinned apps abort the handshake before any HTTP flow exists, so they never
reach the .flow file. This logs the SNI of every failed handshake to
data/raw/<name>.tls-failures.txt so you can still learn which hosts the app
contacts and confirm pinning as the cause.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mitmproxy import tls

_OUT = Path(os.environ.get("SNIFF_TLS_LOG", "data/raw/tls-failures.txt"))
_OUT.parent.mkdir(parents=True, exist_ok=True)
log = logging.getLogger(__name__)


def _record(side: str, data: tls.TlsData) -> None:
    sni = data.conn.sni or "<no sni>"
    err = data.conn.error or ""
    with _OUT.open("a") as f:
        f.write(f"{side}\t{sni}\t{err}\n")
    log.warning(f"{side} TLS failed (pinning?): {sni} {err}")


def tls_failed_client(data: tls.TlsData) -> None:
    _record("client", data)


def tls_failed_server(data: tls.TlsData) -> None:
    _record("server", data)
