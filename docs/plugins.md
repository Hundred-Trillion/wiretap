# Wiretap Plugins & Decoders

Wiretap uses a modular architecture, meaning new protocols, site-specific analyzers, and custom binary decoders can be added without modifying the core system.

---

## Writing a Custom Decoder

All decoders must implement the `Decoder` protocol defined in `wiretap.decoders.base`:

```python
from typing import Any
from wiretap.core.enums import DecoderStatus
from wiretap.decoders.base import DecodeResult

class CustomBinaryDecoder:
    name: str = "my_custom_decoder"
    priority: int = 500  # Lower priorities run first

    def can_decode(self, data: bytes, content_type: str | None = None) -> float:
        # Return a confidence score between 0.0 and 1.0.
        # Returning 0.0 means the registry will skip this decoder.
        if content_type == "application/x-my-format":
            return 1.0
        if len(data) > 4 and data[:4] == b"\xde\xad\xbe\xef":
            return 0.8
        return 0.0

    def decode(self, data: bytes) -> DecodeResult:
        try:
            # Implement your custom decoding logic here
            decoded_val = parse_my_format(data)
            return DecodeResult(
                status=DecoderStatus.SUCCESS,
                data=decoded_val,
                confidence=0.9,
                encoding=self.name
            )
        except Exception as e:
            return DecodeResult(
                status=DecoderStatus.FAILED,
                encoding=self.name,
                error=str(e)
            )
```

To register your decoder, add it to the `wiretap.decoders` entry-point group in your plugin package's `pyproject.toml`:

```toml
[project.entry-points."wiretap.decoders"]
my_decoder = "my_package.decoders:CustomBinaryDecoder"
```

---

## Writing a Custom Plugin

Site-specific plugins or customized protocol mappers implement the `Plugin` protocol from `wiretap.plugins.base`:

```python
from typing import Any
from uuid import uuid4
from wiretap.core.enums import EventType
from wiretap.core.models import Connection, Frame, Payload, ProtocolEvent
from wiretap.plugins.base import PluginInfo

class DiscordPlugin:
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="discord",
            version="0.1.0",
            description="Analyzes Discord Gateway WebSocket traffic",
            author="Developer",
            target_domains=["discord.com", "gateway.discord.gg"],
        )

    def can_handle(self, connections: list[Connection]) -> bool:
        # Check if this plugin matches the traffic
        return any(domain in conn.url for conn in connections for domain in self.info.target_domains)

    def analyze(
        self,
        connections: list[Connection],
        frames: list[Frame],
        payloads: dict[Any, Payload]
    ) -> list[ProtocolEvent]:
        events = []
        # Implement custom pattern matching on connections or frames
        # (e.g., matching Discord gateway OP codes)
        return events
```

Register your plugin in your `pyproject.toml` under `wiretap.plugins`:

```toml
[project.entry-points."wiretap.plugins"]
discord = "my_package.plugins:DiscordPlugin"
```
