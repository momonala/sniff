"""mitmproxy addon: stream gRPC calls through and log every message to JSONL.

Bidirectional gRPC streams (Firestore Listen/Write) never finish their request
body, so mitmproxy's default buffering would stall them. Streaming means the
bodies never land in the .flow file, so each length-prefixed gRPC message is
decoded here and appended to data/raw/<name>.grpc.jsonl instead.
"""

from __future__ import annotations

import gzip
import json
import os
import time
import zlib
from pathlib import Path

from mitmproxy import http

from sniff.proto import decode as decode_proto

_OUT = Path(os.environ.get("SNIFF_GRPC_LOG", "data/raw/grpc.jsonl"))
_OUT.parent.mkdir(parents=True, exist_ok=True)


def _is_grpc(message: http.Message) -> bool:
    return message.headers.get("content-type", "").startswith("application/grpc")


def _write(flow: http.HTTPFlow, kind: str, **fields) -> None:
    record = {"ts": time.time(), "flow": flow.id, "url": flow.request.pretty_url, "kind": kind, **fields}
    with _OUT.open("a") as f:
        f.write(json.dumps(record) + "\n")


def _decompress(payload: bytes, encoding: str) -> bytes:
    if encoding == "gzip":
        return gzip.decompress(payload)
    if encoding == "deflate":
        return zlib.decompress(payload)
    raise ValueError(f"unsupported grpc-encoding {encoding!r}")


class _Recorder:
    """Passes chunks through unchanged while splitting them into gRPC frames."""

    def __init__(self, flow: http.HTTPFlow, direction: str, message: http.Message) -> None:
        self.flow = flow
        self.direction = direction
        self.encoding = message.headers.get("grpc-encoding", "identity")
        self.buf = b""
        self.count = 0

    def __call__(self, chunk: bytes) -> bytes:
        self.buf += chunk
        while len(self.buf) >= 5:
            length = int.from_bytes(self.buf[1:5], "big")
            if len(self.buf) < 5 + length:
                break
            compressed, payload = self.buf[0] & 1, self.buf[5 : 5 + length]
            self.buf = self.buf[5 + length :]
            self._log(payload, compressed)
        return chunk

    def _log(self, payload: bytes, compressed: int) -> None:
        try:
            body = {"protobuf": decode_proto(_decompress(payload, self.encoding) if compressed else payload)}
        except (ValueError, OSError, EOFError, zlib.error):
            body = {"hex": payload.hex()}
        _write(self.flow, self.direction, index=self.count, body=body)
        self.count += 1


def requestheaders(flow: http.HTTPFlow) -> None:
    if _is_grpc(flow.request):
        _write(flow, "start", method=flow.request.method, headers=dict(flow.request.headers))
        flow.request.stream = _Recorder(flow, "request", flow.request)


def responseheaders(flow: http.HTTPFlow) -> None:
    if flow.response and _is_grpc(flow.response):
        flow.response.stream = _Recorder(flow, "response", flow.response)


def response(flow: http.HTTPFlow) -> None:
    if flow.response and _is_grpc(flow.response):
        trailers = flow.response.trailers or flow.response.headers
        _write(flow, "end", grpc_status=trailers.get("grpc-status"), grpc_message=trailers.get("grpc-message"))


def error(flow: http.HTTPFlow) -> None:
    if _is_grpc(flow.request):
        _write(flow, "error", error=str(flow.error))
