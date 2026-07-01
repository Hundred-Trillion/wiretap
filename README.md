# Wiretap

🔍 **Wiretap** is a spec-driven browser protocol analysis framework and independent native WebSocket client. It captures, analyzes, and reproduces real-time communication from web applications at the network layer — without scraping DOM or modifying target apps.

---

## What It Does

Wiretap works in two modes:

1. **Capture Mode** — Launches a Chromium browser via Playwright + CDP and records every HTTP request, WebSocket frame, and SSE event into a local SQLite database with forensic accuracy.
2. **Native Mode** — Connects directly to backend WebSocket servers using saved authentication cookies and declarative JSON specifications, streaming live data with zero browser overhead (~35 MB RAM).

---

## Features

- **Protocol-Layer Capture**: Records HTTP, WebSocket, and Server-Sent Events (SSE) traffic via the Chrome DevTools Protocol (CDP).
- **Forensic Accuracy**: Preserves raw payloads, headers, cookies, handshakes, timestamps, and frame sequence numbers.
- **Extensible Decoders**: Decodes payloads using UTF-8, UTF-16, JSON, XML, Gzip, Zlib, Brotli, MessagePack, and CBOR. Also includes wire-format heuristic detectors for Protocol Buffers and FlatBuffers (schema required for full decode).
- **Protocol Discovery**: Automatically identifies authentication sequences, heartbeats, keep-alives, and request-response patterns.
- **Interactive Visualizations**: Generates self-contained HTML dashboards with event timelines, connection graphs, and payload explorers.
- **Session Replay**: Step through captured traffic frame-by-frame from the CLI.
- **Spec-Driven Protocol Reproduction**: Connect directly to backend WebSockets using declarative JSON specifications (`specs/`) without starting a browser.
- **Drift Detection**: Monitors protocol mutations and validates incoming packets against layout specifications in real-time.
- **Protocol Replay Simulation**: Simulate captured streams offline with pause, step, and speed controls.

---

## Installation

Requires Python 3.12+.

```bash
git clone https://github.com/Hundred-Trillion/wiretap.git
cd wiretap
pip install -e .

# Install Playwright browser binaries (for capture mode only)
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
Connect directly to the backend WebSocket server using a saved session token and stream live data:
```bash
wiretap trace quotex --token <session-token> --asset BTCUSD_otc
```

### 3. Replay & Simulation
Simulate protocol playback from captured SQLite session logs offline:
```bash
wiretap simulate <session-id> --speed 10
```

### 4. Protocol Drift Doctor
Diagnose layout changes or unknown packets in a session:
```bash
wiretap doctor <session-id>
```

### 5. Generate Reports & Visualizations
Produce Markdown documentation and interactive HTML files:
```bash
wiretap report <session-id> --output ./my-reports
```

---

## CLI Reference

```bash
wiretap --help
```

| Command | Description |
|---|---|
| `capture <url>` | Start capturing browser traffic |
| `analyze <session>` | Run protocol discovery engine |
| `inspect <session>` | Tabular summary of captured frames |
| `replay <session>` | Step through frames interactively |
| `report <session>` | Generate JSON, Markdown, and HTML reports |
| `decode <data>` | Decode hex/base64 data with all decoders |
| `compare <a> <b>` | Diff two capture sessions |
| `stats <session>` | Print session traffic statistics |
| `plugins` | List installed decoders and plugins |
| `trace <protocol>` | Stream live protocol updates (no browser) |
| `simulate <session>` | Simulate protocol playback offline |
| `doctor <session>` | Analyze protocol drift compliance |

---

## Architecture

```
wiretap/
├── capture/          # Playwright + CDP traffic recording
├── core/             # Domain models, adapters, protocol client, event bus
├── analysis/         # Discovery, clustering, structural analysis, correlation
├── decoders/         # Pluggable payload decoders (UTF-8, JSON, Gzip, etc.)
├── drift/            # Runtime drift detection against layout specs
├── protocols/        # Protocol implementations (Quotex, extensible)
├── replay/           # Offline replay simulator
├── reports/          # Markdown report generator
├── visualization/    # HTML timeline and connection graph generators
├── validators/       # Price field validation engine
├── plugins/          # Plugin registry (entry-point based)
└── specs/            # Declarative JSON protocol specifications
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
