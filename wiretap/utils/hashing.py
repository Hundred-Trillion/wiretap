"""Hashing and encoding utilities."""

from __future__ import annotations

import base64
import hashlib


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def to_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("ascii")


def from_base64(encoded: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(encoded)


def hex_dump(data: bytes, width: int = 16, max_lines: int = 32) -> str:
    """Generate a formatted hex dump of binary data.

    Args:
        data: Raw bytes to dump.
        width: Number of bytes per line.
        max_lines: Maximum number of lines to generate.

    Returns:
        Formatted hex dump string with offset, hex, and ASCII columns.
    """
    lines = []
    for i in range(0, min(len(data), width * max_lines), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")

    if len(data) > width * max_lines:
        lines.append(f"... ({len(data) - width * max_lines} more bytes)")

    return "\n".join(lines)
