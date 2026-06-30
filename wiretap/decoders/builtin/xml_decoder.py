"""XML decoder."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult


def _element_to_dict(element: ET.Element) -> dict:
    """Convert an XML element tree to a nested dictionary."""
    result: dict = {"tag": element.tag}
    if element.attrib:
        result["attributes"] = dict(element.attrib)
    if element.text and element.text.strip():
        result["text"] = element.text.strip()
    children = [_element_to_dict(child) for child in element]
    if children:
        result["children"] = children
    return result


class XMLDecoder:
    """Decodes payloads as XML."""

    name: str = "xml"
    priority: int = 60

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        if content_type and ("xml" in content_type or "html" in content_type):
            return 0.9
        stripped = data.lstrip()
        if stripped.startswith(b"<?xml") or stripped.startswith(b"<"):
            return 0.5
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            root = ET.fromstring(data)
            parsed = _element_to_dict(root)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=parsed,
                confidence=0.85,
                encoding="xml",
            )
        except ET.ParseError as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding="xml",
                error=str(e),
            )
