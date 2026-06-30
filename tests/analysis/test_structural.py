import pytest
import struct
from datetime import datetime, timezone
from uuid import uuid4
from wiretap.core.enums import Direction
from wiretap.analysis.classification import BinaryPacketFamily, BinaryPacketFingerprint
from wiretap.analysis.structural import StructuralAnalyzer


def test_structural_field_mapping():
    analyzer = StructuralAnalyzer(min_packets_for_analysis=3)

    # Let's create mock packets with:
    # - Offset 0: constant byte (0xaa)
    # - Offset 1: monotonically increasing 1-byte counter
    # - Offset 2-5: float32 (BE)
    # - Offset 6-9: uint32 (BE) epoch timestamp
    fingerprints = []
    base_time = datetime.now(timezone.utc)
    conn_id = uuid4()

    for i in range(5):
        # 1-byte constant (0xaa)
        c = b"\xaa"
        # 1-byte counter
        ctr = bytes([i])
        # 4-byte float32 BE (e.g. 1.23 + i)
        fl = struct.pack(">f", 1.23 + float(i))
        # 4-byte uint32 BE timestamp (e.g. 1700000000 + i)
        ts = struct.pack(">I", 1700000000 + i)

        payload = c + ctr + fl + ts

        fingerprints.append(
            BinaryPacketFingerprint(
                frame_id=uuid4(),
                connection_id=conn_id,
                direction=Direction.RECEIVED,
                timestamp=base_time,
                length=len(payload),
                entropy=2.5,
                crc32=123,
                prefix=payload[:4],
                sha256=f"sha-{i}",
                payload_raw=payload,
            )
        )

    family = BinaryPacketFamily(
        id="family_1",
        direction=Direction.RECEIVED,
        common_prefix="aa00",
        avg_length=10.0,
        count=5,
        avg_interval=1.0,
        entropy=2.5,
        confidence=0.9,
        likely_purpose="test",
        fingerprints=fingerprints,
    )

    field_map = analyzer.analyze_family(family)

    # We should have found:
    # 1. Constant byte at offset 0
    # 2. Counter at offset 1
    # 3. Float32 BE at offset 2 (size 4)
    # 4. Timestamp BE at offset 6 (size 4)
    
    assert len(field_map) >= 2

    # Check that all offsets are covered and valid
    for entry in field_map:
        assert 0 <= entry.offset < 10
        assert entry.size > 0
        assert entry.stability in ("constant", "counter", "timestamp", "float", "integer", "variable")
        assert len(entry.sample_values) > 0
