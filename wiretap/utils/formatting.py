"""Rich formatting helpers and display utilities."""

from __future__ import annotations

from datetime import datetime, timezone


def format_bytes(size: int) -> str:
    """Format a byte count as a human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        Formatted string (e.g., '1.5 MB', '320 B', '2.1 GB').
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024:
            if unit == "B":
                return f"{size} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024  # type: ignore[assignment]
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted string (e.g., '2m 30s', '1h 15m', '500ms').
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m"


def format_timestamp(dt: datetime) -> str:
    """Format a datetime as a concise ISO-like string.

    Args:
        dt: Datetime object.

    Returns:
        Formatted string (e.g., '2024-01-15 14:30:05.123').
    """
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def truncate(text: str, max_length: int = 80) -> str:
    """Truncate text to max_length, adding ellipsis if needed.

    Args:
        text: Text to truncate.
        max_length: Maximum length including ellipsis.

    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
