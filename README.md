# Wiretap

🔍 **Wiretap** is a professional, reusable browser protocol analysis framework that observes how modern web applications communicate over HTTP, WebSockets, Server-Sent Events (SSE), and related browser networking APIs. 

Unlike HTML scrapers or DOM-based testing tools, Wiretap operates entirely at the browser protocol layer using Playwright and the Chrome DevTools Protocol (CDP) for forensic accuracy. It is designed to help systems engineers, protocol specialists, and reverse engineers document and understand browser network communication without modifying target web applications.

---

## Features

- **Protocol-Layer Capture**: Record HTTP/1.x, HTTP/2, WebSockets, and Server-Sent Events (SSE) directly from the browser.
- **Forensic Accuracy**: Preserves raw request/response payloads, headers, cookies, connection handshakes, timestamps, and sequence numbers.
- **Extensible Decoders**: Attempts to decode binary and text payloads using UTF-8, UTF-16, JSON, XML, Gzip, Zlib, Brotli, MessagePack, CBOR, Protocol Buffers (wire-format heuristics), and FlatBuffers (heuristics).
- **Evidence-Based Protocol Discovery**: Automatically detects authentication sequences, keep-alives, heartbeats, request-response mappings, and binary event families.
- **Interactive Visualizations**: Generates self-contained, offline HTML dashboards containing event timelines, domain connection graphs, and payload inspectors.
- **Session Replay**: Step through captured traffic frame-by-frame, apply filters, and switch decoders on the fly from the CLI.
- **Plugin-Driven Architecture**: Easily extend analysis and decoding via standard Python entry points.
- **Spec-Driven Protocol Reproduction**: Connect directly to backend WebSockets using declarative JSON specifications (under `specs/`) without starting a browser.
- **Drift & Layout Doctor**: Monitor protocol mutations and field shifts dynamically at runtime.
- **Protocol Replay Simulation**: Simulate real-time captured streams offline with pause/step controls and speed multipliers.

---

## Installation

Ensure you have Python 3.12+ installed. Clone this repository and install it in editable mode:

```bash
git clone https://github.com/Hundred-Trillion/wiretap.git
cd wiretap
pip install -e .

# Install Playwright browser binaries
playwright install chromium
```

---

## Quick Start

### 1. Capture a Session
Start a headed browser session capturing traffic from a target web app:
```bash
wiretap capture https://example.com --name my-capture-session
```
*Type annotations (e.g. `Clicked Login`, `Loaded Dashboard`) into the terminal while capturing to correlate user actions with network events.*

### 2. Live Spec-Driven Tracer (No Browser)
Connect directly to the backend WebSocket server using a saved session token and stream live price ticks/payloads:
```bash
wiretap trace quotex --token <session-token> --asset BTCUSD_otc
```

### 3. Replay & Playback Simulator
Simulate protocol playback from your captured SQLite session logs offline:
```bash
wiretap simulate <session-id> --speed 10
```

### 4. Protocol Drift Doctor
Diagnose layout changes or unknown/unregistered packets in a session:
```bash
wiretap doctor <session-id>
```

### 5. Generate Reports & Visualizations
Produce Markdown documentation and interactive HTML files (Timeline, Connection Graph, Payload Explorer):
```bash
wiretap report <session-id> --output ./my-reports
```

---

## CLI Reference

```bash
wiretap --help
```

- `capture <url>`: Start capturing browser traffic.
- `analyze <session>`: Run the protocol discovery engine to find patterns.
- `inspect <session>`: Render a tabular summary of captured frames.
- `replay <session>`: Interactively step through frames in sequence.
- `report <session>`: Write JSON, Markdown, and HTML reports.
- `decode <data>`: Decode arbitrary hex or base64 data using all registry decoders.
- `compare <session-a> <session-b>`: Diff two capture sessions.
- `stats <session>`: Print session traffic statistics.
- `plugins`: List installed decoders and plugins.
- `trace <protocol>`: Connect and trace live protocol updates in real-time.
- `simulate <session>`: Simulate protocol playback from database offline.
- `doctor <session>`: Analyze protocol drift and layout specification compliance.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

