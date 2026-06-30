"""Session replay — step through captured traffic frame-by-frame.

Supports filtering, decoder switching, and payload inspection
for post-capture analysis. Think "Wireshark for browser protocols."
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from wiretap.core.enums import Direction, ProtocolType
from wiretap.core.models import Connection, Frame, Payload
from wiretap.decoders.registry import DecoderRegistry


class SessionReplay:
    """Replay a captured session frame-by-frame.

    Provides a cursor-based interface for stepping through captured
    frames with optional filtering and on-the-fly decoding.

    Usage:
        replay = SessionReplay(connections, frames, payloads, decoder_registry)
        replay.apply_filter(protocol=ProtocolType.WEBSOCKET)
        while replay.has_next():
            info = replay.next()
            print(info)
    """

    def __init__(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[UUID, Payload],
        decoder_registry: DecoderRegistry | None = None,
    ) -> None:
        self._connections = {str(c.id): c for c in connections}
        self._all_frames = sorted(frames, key=lambda f: f.timestamp)
        self._payloads = payloads
        self._decoder = decoder_registry
        self._filtered_frames: list[Frame] = list(self._all_frames)
        self._cursor: int = 0

    @property
    def total_frames(self) -> int:
        """Total number of frames after filtering."""
        return len(self._filtered_frames)

    @property
    def current_position(self) -> int:
        """Current cursor position (0-indexed)."""
        return self._cursor

    def has_next(self) -> bool:
        """Check if there are more frames to replay."""
        return self._cursor < len(self._filtered_frames)

    def has_previous(self) -> bool:
        """Check if the cursor can move backward."""
        return self._cursor > 0

    def next(self) -> dict[str, Any] | None:
        """Advance to the next frame and return its details.

        Returns:
            Frame detail dict, or None if at end.
        """
        if not self.has_next():
            return None
        frame = self._filtered_frames[self._cursor]
        self._cursor += 1
        return self._build_frame_info(frame)

    def previous(self) -> dict[str, Any] | None:
        """Move to the previous frame and return its details.

        Returns:
            Frame detail dict, or None if at start.
        """
        if not self.has_previous():
            return None
        self._cursor -= 1
        frame = self._filtered_frames[self._cursor]
        return self._build_frame_info(frame)

    def seek(self, position: int) -> dict[str, Any] | None:
        """Jump to a specific frame position.

        Args:
            position: 0-indexed position.

        Returns:
            Frame detail dict, or None if position invalid.
        """
        if 0 <= position < len(self._filtered_frames):
            self._cursor = position
            return self._build_frame_info(self._filtered_frames[position])
        return None

    def reset(self) -> None:
        """Reset cursor to the beginning."""
        self._cursor = 0

    def apply_filter(
        self,
        protocol: ProtocolType | None = None,
        direction: Direction | None = None,
        url_contains: str | None = None,
        binary_only: bool = False,
        text_only: bool = False,
    ) -> int:
        """Apply filters to the frame list.

        Args:
            protocol: Filter by protocol type.
            direction: Filter by direction.
            url_contains: Filter connections by URL substring.
            binary_only: Show only binary frames.
            text_only: Show only text frames.

        Returns:
            Number of frames after filtering.
        """
        filtered = list(self._all_frames)

        if protocol is not None:
            valid_conns = {
                str(c_id)
                for c_id, c in self._connections.items()
                if c.protocol == protocol
            }
            filtered = [f for f in filtered if str(f.connection_id) in valid_conns]

        if direction is not None:
            filtered = [f for f in filtered if f.direction == direction]

        if url_contains:
            url_lower = url_contains.lower()
            valid_conns = {
                c_id
                for c_id, c in self._connections.items()
                if url_lower in c.url.lower()
            }
            filtered = [f for f in filtered if str(f.connection_id) in valid_conns]

        if binary_only:
            filtered = [f for f in filtered if f.is_binary]

        if text_only:
            filtered = [f for f in filtered if not f.is_binary]

        self._filtered_frames = filtered
        self._cursor = 0
        return len(filtered)

    def clear_filters(self) -> None:
        """Remove all filters and reset to full frame list."""
        self._filtered_frames = list(self._all_frames)
        self._cursor = 0

    def _build_frame_info(self, frame: Frame) -> dict[str, Any]:
        """Build a detailed information dict for a frame."""
        conn = self._connections.get(str(frame.connection_id))
        payload = self._payloads.get(frame.payload_id) if frame.payload_id else None

        info: dict[str, Any] = {
            "position": self._cursor,
            "total": len(self._filtered_frames),
            "frame_id": str(frame.id),
            "timestamp": frame.timestamp.isoformat(),
            "direction": frame.direction.name,
            "sequence": frame.sequence,
            "is_binary": frame.is_binary,
            "opcode": frame.opcode,
            "connection": {
                "url": conn.url if conn else "",
                "protocol": conn.protocol.name if conn else "",
                "method": conn.method if conn else None,
            },
        }

        if payload:
            info["payload"] = {
                "size": payload.size,
                "sha256": payload.sha256,
                "content_type": payload.content_type,
                "hex_preview": payload.raw_bytes[:64].hex(),
            }

            # Attempt text preview
            try:
                info["payload"]["text_preview"] = payload.raw_bytes[:500].decode("utf-8")
            except UnicodeDecodeError:
                info["payload"]["text_preview"] = "(binary data)"

            # Run decoders if available
            if self._decoder:
                results = self._decoder.decode_payload(
                    payload.raw_bytes, payload.content_type
                )
                if results:
                    info["decoded"] = [
                        {
                            "encoding": r.encoding,
                            "confidence": r.confidence,
                            "status": r.status.name,
                        }
                        for r in results[:3]
                    ]

        return info
