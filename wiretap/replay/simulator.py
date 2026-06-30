import sqlite3
import asyncio
import time
from typing import Any, Callable, Optional
from wiretap.core.packets import Packet
from wiretap.protocols.base import BaseProtocolImplementation

class ReplaySimulator:
    def __init__(
        self,
        db_path: str,
        session_id: str,
        protocol: BaseProtocolImplementation,
        speed: float = 1.0
    ):
        self.db_path = db_path
        self.session_id = session_id
        self.protocol = protocol
        self.speed = speed
        self.is_paused = False
        self.frames: list[dict[str, Any]] = []
        self.current_index = 0

    def load(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Load WebSocket frames for session
        cursor.execute("""
            SELECT frames.sequence, frames.direction, frames.is_binary, payloads.raw_bytes, frames.timestamp
            FROM frames
            JOIN payloads ON frames.payload_id = payloads.id
            JOIN connections ON frames.connection_id = connections.id
            WHERE connections.session_id = ?
            ORDER BY frames.sequence ASC;
        """, (self.session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        self.frames = []
        for seq, direction, is_binary, raw_bytes, ts in rows:
            # Parse timestamp if it is a string
            if isinstance(ts, str):
                try:
                    # e.g. "2026-06-30 14:30:47.685009"
                    parsed_ts = time.mktime(time.strptime(ts.split(".")[0], "%Y-%m-%d %H:%M:%S"))
                    if "." in ts:
                        parsed_ts += float("0." + ts.split(".")[1])
                except Exception:
                    parsed_ts = float(seq)  # Fallback to seq-based timing
            else:
                parsed_ts = float(ts) if ts else float(seq)
                
            self.frames.append({
                "sequence": seq,
                "direction": direction,
                "is_binary": bool(is_binary),
                "raw_bytes": raw_bytes,
                "timestamp": parsed_ts
            })
            
        self.current_index = 0
        return len(self.frames)

    async def run(self, callback: Callable[[Packet, dict[str, Any]], None]):
        if not self.frames:
            return
            
        last_ts = self.frames[0]["timestamp"]
        
        while self.current_index < len(self.frames):
            if self.is_paused:
                await asyncio.sleep(0.1)
                continue
                
            frame = self.frames[self.current_index]
            current_ts = frame["timestamp"]
            
            # Simulate real-world spacing between packets
            time_diff = current_ts - last_ts
            if time_diff > 0 and self.speed > 0:
                await asyncio.sleep(time_diff / self.speed)
                
            # Decode the frame using protocol implementation
            # Since incoming packets have an Engine.IO prefix:
            # We must identify the prefix. If it's a binary frame, the first byte is the prefix.
            # If it's text, the first character is the prefix.
            raw_bytes = frame["raw_bytes"]
            is_binary = frame["is_binary"]
            
            try:
                if is_binary:
                    packet_type = raw_bytes[0]
                    payload = raw_bytes[1:]
                else:
                    text_str = raw_bytes.decode("utf-8", errors="ignore")
                    packet_type = int(text_str[0])
                    payload = text_str[1:]
                    
                packet = self.protocol.parse_payload(packet_type, payload)
                callback(packet, frame)
            except Exception as e:
                # Fallback on parsing failure
                pass
                
            last_ts = current_ts
            self.current_index += 1

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def step(self) -> Optional[tuple[Packet, dict[str, Any]]]:
        """Manually process the next packet and return it."""
        if self.current_index >= len(self.frames):
            return None
            
        frame = self.frames[self.current_index]
        self.current_index += 1
        
        raw_bytes = frame["raw_bytes"]
        is_binary = frame["is_binary"]
        
        try:
            if is_binary:
                packet_type = raw_bytes[0]
                payload = raw_bytes[1:]
            else:
                text_str = raw_bytes.decode("utf-8", errors="ignore")
                packet_type = int(text_str[0])
                payload = text_str[1:]
                
            packet = self.protocol.parse_payload(packet_type, payload)
            return packet, frame
        except Exception:
            return None

    def seek(self, index: int):
        if 0 <= index < len(self.frames):
            self.current_index = index
            
    def set_speed(self, speed: float):
        self.speed = max(0.01, speed)
