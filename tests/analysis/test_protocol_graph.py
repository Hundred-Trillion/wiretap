import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from wiretap.core.enums import Direction
from wiretap.core.models import Frame
from wiretap.analysis.classification import BinaryPacketFamily, BinaryPacketFingerprint
from wiretap.analysis.protocol_graph import ProtocolGraphBuilder


def test_protocol_graph_and_chains():
    builder = ProtocolGraphBuilder()

    # Let's create:
    # Frame 1: SENT, family_req, timestamp T
    # Frame 2: RECEIVED, family_resp, timestamp T + 0.1s
    # (Repeated twice to form request-response pattern)
    conn_id = uuid4()
    base_time = datetime.now(timezone.utc)

    f1 = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=base_time,
        payload_id=uuid4(),
        sequence=0,
    )
    f2 = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.RECEIVED,
        timestamp=base_time + timedelta(seconds=0.1),
        payload_id=uuid4(),
        sequence=1,
    )
    f3 = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=base_time + timedelta(seconds=2.0),
        payload_id=uuid4(),
        sequence=2,
    )
    f4 = Frame(
        id=uuid4(),
        connection_id=conn_id,
        direction=Direction.RECEIVED,
        timestamp=base_time + timedelta(seconds=2.1),
        payload_id=uuid4(),
        sequence=3,
    )

    frames = [f1, f2, f3, f4]

    # Map frames to families
    fp1 = BinaryPacketFingerprint(
        frame_id=f1.id,
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=f1.timestamp,
        length=8,
        entropy=1.0,
        crc32=1,
        prefix=b"\x01",
        sha256="sha-1",
        payload_raw=b"\x01\x00\x00\x00\x00\x00\x00\x00",
    )
    fp3 = BinaryPacketFingerprint(
        frame_id=f3.id,
        connection_id=conn_id,
        direction=Direction.SENT,
        timestamp=f3.timestamp,
        length=8,
        entropy=1.0,
        crc32=1,
        prefix=b"\x01",
        sha256="sha-3",
        payload_raw=b"\x01\x00\x00\x00\x00\x00\x00\x00",
    )
    fam_req = BinaryPacketFamily(
        id="family_req",
        direction=Direction.SENT,
        common_prefix="0100",
        avg_length=8.0,
        count=2,
        avg_interval=2.0,
        entropy=1.0,
        confidence=0.9,
        likely_purpose="request",
        fingerprints=[fp1, fp3],
    )

    fp2 = BinaryPacketFingerprint(
        frame_id=f2.id,
        connection_id=conn_id,
        direction=Direction.RECEIVED,
        timestamp=f2.timestamp,
        length=8,
        entropy=1.0,
        crc32=2,
        prefix=b"\x02",
        sha256="sha-2",
        payload_raw=b"\x02\x00\x00\x00\x00\x00\x00\x00",
    )
    fp4 = BinaryPacketFingerprint(
        frame_id=f4.id,
        connection_id=conn_id,
        direction=Direction.RECEIVED,
        timestamp=f4.timestamp,
        length=8,
        entropy=1.0,
        crc32=2,
        prefix=b"\x02",
        sha256="sha-4",
        payload_raw=b"\x02\x00\x00\x00\x00\x00\x00\x00",
    )
    fam_resp = BinaryPacketFamily(
        id="family_resp",
        direction=Direction.RECEIVED,
        common_prefix="0200",
        avg_length=8.0,
        count=2,
        avg_interval=2.0,
        entropy=1.0,
        confidence=0.9,
        likely_purpose="response",
        fingerprints=[fp2, fp4],
    )

    families = [fam_req, fam_resp]

    # Graph
    transitions = builder.build_graph(families, frames)
    assert len(transitions) >= 1
    # Check transition from req -> resp
    req_to_resp = next(t for t in transitions if t.from_family == "family_req" and t.to_family == "family_resp")
    assert req_to_resp.count == 2
    assert req_to_resp.avg_interval == pytest.approx(0.1, abs=0.01)

    # Inferred Request-Response chain
    chains = builder.infer_chains(families, frames)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.request_family == "family_req"
    assert chain.response_family == "family_resp"
    assert chain.confidence == 1.0
    assert chain.avg_latency == pytest.approx(0.1, abs=0.01)
