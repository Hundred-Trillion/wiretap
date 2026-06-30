"""Interactive HTML payload explorer.

Generates a standalone HTML file for inspecting captured payloads
with hex view, text view, and decoded view side-by-side.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from wiretap.core.models import Connection, Frame, Payload
from wiretap.utils.formatting import format_bytes


def generate_payload_explorer(
    output_path: Path,
    connections: list[Connection],
    frames: list[Frame],
    payloads: dict[UUID, Payload],
    decoded_results: dict[UUID, Any] | None = None,
    session_name: str = "Capture Session",
) -> Path:
    """Generate an interactive HTML payload explorer.

    Args:
        output_path: Path to write the HTML file.
        connections: All connections in the session.
        frames: All frames in the session.
        payloads: Mapping of payload_id → Payload.
        decoded_results: Optional mapping of payload_id → decoded data.
        session_name: Title for the explorer.

    Returns:
        Path to the generated HTML file.
    """
    decoded_results = decoded_results or {}
    conn_map = {str(c.id): c for c in connections}

    # Build payload entries
    entries = []
    for frame in sorted(frames, key=lambda f: f.timestamp):
        if not frame.payload_id or frame.payload_id not in payloads:
            continue
        payload = payloads[frame.payload_id]
        conn = conn_map.get(str(frame.connection_id))

        # Limit payload preview for performance
        text_preview = ""
        try:
            text_preview = payload.raw_bytes[:2000].decode("utf-8", errors="replace")
        except Exception:
            text_preview = "(binary data)"

        decoded = decoded_results.get(frame.payload_id)
        decoded_str = ""
        if decoded is not None:
            try:
                decoded_str = json.dumps(decoded, indent=2, default=str)[:5000]
            except Exception:
                decoded_str = str(decoded)[:5000]

        entries.append({
            "timestamp": frame.timestamp.isoformat(),
            "direction": frame.direction.name,
            "url": conn.url if conn else "",
            "protocol": conn.protocol.name if conn else "",
            "size": payload.size,
            "size_fmt": format_bytes(payload.size),
            "sha256": payload.sha256,
            "is_binary": frame.is_binary,
            "hex": payload.raw_bytes[:512].hex(),
            "text": text_preview,
            "decoded": decoded_str,
        })

    entries_json = json.dumps(entries[:500], indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Payload Explorer — {session_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e8;
            display: grid;
            grid-template-columns: 380px 1fr;
            grid-template-rows: auto 1fr;
            height: 100vh;
        }}
        .header {{
            grid-column: 1 / -1;
            padding: 12px 20px;
            background: #111122;
            border-bottom: 1px solid #1e1e2e;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .header h1 {{ font-size: 1.1rem; color: #a78bfa; }}
        .header input {{
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            color: #e0e0e8;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            width: 250px;
        }}
        .list {{
            overflow-y: auto;
            border-right: 1px solid #1e1e2e;
        }}
        .list-item {{
            padding: 10px 14px;
            border-bottom: 1px solid #111122;
            cursor: pointer;
            font-size: 0.78rem;
            transition: background 0.15s;
        }}
        .list-item:hover {{ background: #1a1a2e; }}
        .list-item.selected {{ background: #1e1b3a; border-left: 3px solid #a78bfa; }}
        .list-item .meta {{ color: #6b7280; font-size: 0.7rem; }}
        .list-item .dir-sent {{ color: #f59e0b; }}
        .list-item .dir-received {{ color: #3b82f6; }}
        .detail {{
            overflow-y: auto;
            padding: 16px;
        }}
        .detail-section {{
            margin-bottom: 16px;
        }}
        .detail-section h3 {{
            font-size: 0.85rem;
            color: #a78bfa;
            margin-bottom: 8px;
            display: flex;
            gap: 8px;
        }}
        .tab-buttons {{
            display: flex;
            gap: 4px;
            margin-bottom: 8px;
        }}
        .tab-btn {{
            padding: 4px 12px;
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            border-radius: 4px;
            color: #9ca3af;
            cursor: pointer;
            font-size: 0.75rem;
        }}
        .tab-btn.active {{ background: #2a1e5e; color: #a78bfa; border-color: #a78bfa; }}
        pre {{
            background: #0d0d18;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #1e1e2e;
            overflow-x: auto;
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 400px;
            overflow-y: auto;
        }}
        .empty {{ color: #6b7280; padding: 40px; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Payload Explorer</h1>
        <input type="text" id="search" placeholder="Search URL, SHA256..." />
    </div>
    <div class="list" id="list"></div>
    <div class="detail" id="detail">
        <div class="empty">Select a payload from the list</div>
    </div>

    <script>
    const entries = {entries_json};
    let selected = -1;

    function renderList(filter) {{
        const list = document.getElementById('list');
        const f = (filter || '').toLowerCase();
        list.innerHTML = entries.map((e, i) => {{
            if (f && !e.url.toLowerCase().includes(f) && !e.sha256.includes(f)) return '';
            const dirClass = e.direction === 'SENT' ? 'dir-sent' : 'dir-received';
            return `<div class="list-item ${{i === selected ? 'selected' : ''}}" onclick="selectItem(${{i}})">
                <span class="${{dirClass}}">${{e.direction}}</span>
                <span style="color:#9ca3af">${{e.protocol}}</span>
                <span>${{e.size_fmt}}</span>
                <div class="meta">${{e.url.substring(0, 50)}}</div>
            </div>`;
        }}).join('');
    }}

    function selectItem(i) {{
        selected = i;
        renderList(document.getElementById('search').value);
        renderDetail(entries[i]);
    }}

    function renderDetail(e) {{
        const detail = document.getElementById('detail');
        let decodedHtml = '<pre>(no decoded data)</pre>';
        if (e.decoded) {{
            decodedHtml = `<pre>${{escapeHtml(e.decoded)}}</pre>`;
        }}
        detail.innerHTML = `
            <div class="detail-section">
                <h3>📋 Metadata</h3>
                <pre>${{JSON.stringify({{
                    timestamp: e.timestamp,
                    direction: e.direction,
                    url: e.url,
                    protocol: e.protocol,
                    size: e.size_fmt,
                    sha256: e.sha256,
                    is_binary: e.is_binary,
                }}, null, 2)}}</pre>
            </div>
            <div class="detail-section">
                <h3>📝 Text View</h3>
                <pre>${{escapeHtml(e.text)}}</pre>
            </div>
            <div class="detail-section">
                <h3>🔢 Hex View</h3>
                <pre>${{formatHex(e.hex)}}</pre>
            </div>
            <div class="detail-section">
                <h3>🔓 Decoded</h3>
                ${{decodedHtml}}
            </div>
        `;
    }}

    function escapeHtml(str) {{
        return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }}

    function formatHex(hex) {{
        let result = '';
        for (let i = 0; i < hex.length; i += 32) {{
            const chunk = hex.substring(i, i + 32);
            const offset = (i / 2).toString(16).padStart(8, '0');
            const pairs = chunk.match(/.{{1,2}}/g) || [];
            result += offset + '  ' + pairs.join(' ') + '\\n';
        }}
        return result || '(empty)';
    }}

    document.getElementById('search').addEventListener('input', (e) => {{
        renderList(e.target.value);
    }});

    renderList('');
    </script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path
