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

### 2. View Statistics
Summarize connection counts, protocols, bandwidth, and payload size metrics:
```bash
wiretap stats <session-id>
```

### 3. Generate Reports & Visualizations
Produce Markdown documentation and interactive HTML files (Timeline, Connection Graph, Payload Explorer):
```bash
wiretap report <session-id> --output ./my-reports
```

### 4. Interactive Frame Replay
Step through the captured traffic frame-by-frame:
```bash
wiretap replay <session-id> --protocol WEBSOCKET
```
*Use keys `n` (next), `p` (prev), `g <index>` (goto frame), and `q` (quit).*

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

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
