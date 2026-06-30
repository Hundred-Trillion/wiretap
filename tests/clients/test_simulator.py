import pytest
import sqlite3
import tempfile
import os
import asyncio
from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
from wiretap.replay.simulator import ReplaySimulator
from wiretap.core.packets import PriceTick, Heartbeat

def test_replay_simulator():
    # Setup temporary database
    db_fd, db_path = tempfile.mkstemp()
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create necessary tables
        cursor.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY);")
        cursor.execute("CREATE TABLE connections (id TEXT PRIMARY KEY, session_id TEXT, protocol TEXT, url TEXT);")
        cursor.execute("CREATE TABLE payloads (id TEXT PRIMARY KEY, raw_bytes BLOB);")
        cursor.execute("CREATE TABLE frames (id TEXT PRIMARY KEY, connection_id TEXT, sequence INTEGER, direction TEXT, is_binary INTEGER, payload_id TEXT, timestamp TEXT);")
        
        # Insert mock session, connection, payloads
        session_id = "test-session-uuid"
        conn_id = "conn-1"
        cursor.execute("INSERT INTO sessions VALUES (?);", (session_id,))
        cursor.execute("INSERT INTO connections VALUES (?, ?, 'WEBSOCKET', 'wss://ws2.qxbroker.com/socket.io/');", (conn_id, session_id))
        
        # Binary frame: Engine.IO packet type 4 + '[["BTCUSD_otc",1782829846.783,191844.52,1]]'
        tick_bytes = b"\x04" + b'[["BTCUSD_otc",1782829846.783,191844.52,1]]'
        # Text frame: Engine.IO packet type 2 (ping)
        ping_bytes = b"2"
        
        cursor.execute("INSERT INTO payloads VALUES ('p1', ?);", (sqlite3.Binary(tick_bytes),))
        cursor.execute("INSERT INTO payloads VALUES ('p2', ?);", (sqlite3.Binary(ping_bytes),))
        
        # Insert frames
        cursor.execute("INSERT INTO frames VALUES ('f1', ?, 1, 'RECEIVED', 1, 'p1', '2026-06-30 14:30:47.100');", (conn_id,))
        cursor.execute("INSERT INTO frames VALUES ('f2', ?, 2, 'RECEIVED', 0, 'p2', '2026-06-30 14:30:47.200');", (conn_id,))
        
        conn.commit()
        conn.close()
        
        # Load implementation
        spec_dir = os.path.join(os.getcwd(), "specs", "quotex", "v1")
        impl = QuotexProtocolImplementation(spec_dir)
        
        sim = ReplaySimulator(db_path, session_id, impl, speed=100.0)
        loaded = sim.load()
        assert loaded == 2
        
        # Step packets manually
        p1_res = sim.step()
        assert p1_res is not None
        packet1, frame1 = p1_res
        assert isinstance(packet1, PriceTick)
        assert packet1.asset == "BTCUSD_otc"
        
        p2_res = sim.step()
        assert p2_res is not None
        packet2, frame2 = p2_res
        assert isinstance(packet2, Heartbeat)
        assert packet2.direction == "ping"
        
        assert sim.step() is None
        
    finally:
        os.close(db_fd)
        os.unlink(db_path)
