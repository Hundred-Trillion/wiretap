import pytest
import json
import gzip
import zlib
from wiretap.core.enums import DecoderStatus
from wiretap.decoders.builtin.utf8 import UTF8Decoder
from wiretap.decoders.builtin.json_decoder import JSONDecoder
from wiretap.decoders.builtin.gzip_decoder import GzipDecoder
from wiretap.decoders.builtin.zlib_decoder import ZlibDecoder
from wiretap.decoders.builtin.protobuf_heuristic import ProtobufHeuristicDecoder

def test_utf8_decoder():
    dec = UTF8Decoder()
    raw = "hello world".encode("utf-8")
    assert dec.can_decode(raw, "text/plain") > 0.0
    res = dec.decode(raw)
    assert res.status == DecoderStatus.SUCCESS
    assert res.data == "hello world"

def test_json_decoder():
    dec = JSONDecoder()
    raw = json.dumps({"key": "value"}).encode("utf-8")
    assert dec.can_decode(raw, "application/json") > 0.0
    res = dec.decode(raw)
    assert res.status == DecoderStatus.SUCCESS
    assert res.data == {"key": "value"}

def test_gzip_decoder():
    dec = GzipDecoder()
    orig = b"data to compress"
    compressed = gzip.compress(orig)
    assert dec.can_decode(compressed) > 0.0
    res = dec.decode(compressed)
    assert res.status == DecoderStatus.SUCCESS
    assert res.data == orig

def test_zlib_decoder():
    dec = ZlibDecoder()
    orig = b"zlib data"
    compressed = zlib.compress(orig)
    assert dec.can_decode(compressed) > 0.0
    res = dec.decode(compressed)
    assert res.status == DecoderStatus.SUCCESS
    assert res.data == orig

def test_protobuf_heuristic_decoder():
    dec = ProtobufHeuristicDecoder()
    # Simple manually constructed protobuf: Field 1 (varint) = 150
    # Tag: (1 << 3) | 0 = 8. Varint 150: 96 01.
    raw = b"\x08\x96\x01"
    res = dec.decode(raw)
    assert res.status == DecoderStatus.PARTIAL
    assert res.data["fields"][0]["field_number"] == 1
    assert res.data["fields"][0]["value"] == 150
