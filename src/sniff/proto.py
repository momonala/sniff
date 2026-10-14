"""Schema-less protobuf decoder for reverse-engineering binary API bodies.

Produces a nested dict keyed by field number. Every field value is a list,
one entry per occurrence, so the shape does not change between a repeated
field with one element and a singular one. Length-delimited fields are
decoded as nested messages when they parse cleanly, otherwise shown as
UTF-8 text or hex. No .proto needed.
"""

from __future__ import annotations

import struct
from typing import Any

_VARINT, _I64, _LEN, _I32 = 0, 1, 2, 5
_MAX_DEPTH = 12


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def _parse(buf: bytes, depth: int) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        field, wt = key >> 3, key & 7
        if field == 0:
            raise ValueError("field 0")
        if wt == _VARINT:
            v, i = _varint(buf, i)
        elif wt == _I64:
            if i + 8 > len(buf):
                raise ValueError("truncated i64")
            v = _fixed(buf[i : i + 8], "<d", "<q")
            i += 8
        elif wt == _I32:
            if i + 4 > len(buf):
                raise ValueError("truncated i32")
            v = _fixed(buf[i : i + 4], "<f", "<i")
            i += 4
        elif wt == _LEN:
            n, i = _varint(buf, i)
            if i + n > len(buf):
                raise ValueError("truncated bytes")
            v = _bytes(buf[i : i + n], depth)
            i += n
        else:
            raise ValueError(f"unsupported wire type {wt}")
        out.setdefault(str(field), []).append(v)
    return out


def _fixed(raw: bytes, ffmt: str, ifmt: str) -> Any:
    f = struct.unpack(ffmt, raw)[0]
    i = struct.unpack(ifmt, raw)[0]
    # Prefer the float reading when it looks like a sane real number (coords etc).
    if f == f and abs(f) < 1e9 and (abs(f) > 1e-6 or f == 0):
        return {"float": f, "int": i}
    return i


def _bytes(raw: bytes, depth: int) -> Any:
    """Printable text if it is one, else a nested message if it parses, else hex.

    Strictly printable (no control chars) so a sub-message such as tag 0x0a
    plus a UUID is not mistaken for a string, while short codes like "A388"
    that happen to parse as a message are kept as text.
    """
    if not raw:
        return ""
    try:
        s = raw.decode("utf-8")
        if s.isprintable():
            return s
    except UnicodeDecodeError:
        pass
    if depth < _MAX_DEPTH:
        try:
            return _parse(raw, depth + 1)
        except ValueError:
            pass
    return {"hex": raw.hex()}


def decode(raw: bytes) -> dict[str, list[Any]]:
    """Decode bytes as a protobuf message. Raises ValueError if they are not one."""
    return _parse(raw, 0)
