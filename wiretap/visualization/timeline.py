"""Interactive HTML timeline visualization.

Generates a standalone HTML file with a scrollable, zoomable timeline
of all captured events — connections, frames, and annotations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from wiretap.core.models import Annotation, Connection, Frame
from wiretap.utils.formatting import format_bytes, format_timestamp


def generate_timeline(
    output_path: Path,
    connections: list[Connection],
    frames: list[Frame],
    annotations: list[Annotation],
    session_name: str = "Capture Session",
) -> Path:
    """Generate an interactive HTML timeline.

    Args:
        output_path: Path to write the HTML file.
        connections: All connections in the session.
        frames: All frames in the session.
        annotations: User annotations.
        session_name: Title for the timeline.

    Returns:
        Path to the generated HTML file.
    """
    # Build timeline data
    events_data: list[dict[str, Any]] = []
    conn_map = {str(c.id): c for c in connections}

    for frame in sorted(frames, key=lambda f: f.timestamp):
        conn = conn_map.get(str(frame.connection_id))
        events_data.append({
            "time": frame.timestamp.isoformat(),
            "type": "frame",
            "direction": frame.direction.name,
            "url": conn.url if conn else "",
            "protocol": conn.protocol.name if conn else "",
            "is_binary": frame.is_binary,
            "sequence": frame.sequence,
        })

    for ann in annotations:
        events_data.append({
            "time": ann.timestamp.isoformat(),
            "type": "annotation",
            "text": ann.text,
        })

    events_json = json.dumps(events_data, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Timeline — {session_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0f;
            color: #e0e0e8;
            padding: 24px;
        }}
        h1 {{
            font-size: 1.5rem;
            color: #a78bfa;
            margin-bottom: 24px;
            border-bottom: 1px solid #1e1e2e;
            padding-bottom: 12px;
        }}
        .controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .controls input, .controls select {{
            background: #1a1a2e;
            border: 1px solid #2a2a3e;
            color: #e0e0e8;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.875rem;
        }}
        .controls input:focus, .controls select:focus {{
            outline: none;
            border-color: #a78bfa;
        }}
        .timeline {{
            position: relative;
            padding-left: 60px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 28px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(180deg, #a78bfa, #3b82f6, #06b6d4);
        }}
        .event {{
            position: relative;
            margin-bottom: 4px;
            padding: 8px 14px;
            background: #111122;
            border-radius: 8px;
            border: 1px solid #1e1e2e;
            font-size: 0.8rem;
            transition: all 0.15s ease;
            cursor: pointer;
        }}
        .event:hover {{
            background: #1a1a2e;
            border-color: #a78bfa;
            transform: translateX(4px);
        }}
        .event::before {{
            content: '';
            position: absolute;
            left: -38px;
            top: 50%;
            transform: translateY(-50%);
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #a78bfa;
        }}
        .event.sent::before {{ background: #f59e0b; }}
        .event.received::before {{ background: #3b82f6; }}
        .event.annotation::before {{ background: #10b981; }}
        .event .time {{ color: #6b7280; font-size: 0.7rem; }}
        .event .direction {{ font-weight: 600; }}
        .event .direction.sent {{ color: #f59e0b; }}
        .event .direction.received {{ color: #3b82f6; }}
        .event .url {{ color: #9ca3af; font-size: 0.75rem; }}
        .event .protocol-badge {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.65rem;
            font-weight: 600;
        }}
        .protocol-HTTP {{ background: #1e3a5f; color: #60a5fa; }}
        .protocol-WEBSOCKET {{ background: #1e3a2f; color: #34d399; }}
        .protocol-SSE {{ background: #3a2f1e; color: #fbbf24; }}
        .protocol-FETCH {{ background: #2f1e3a; color: #c084fc; }}
        .annotation-text {{ color: #10b981; font-weight: 600; }}
        .stats {{
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .stat {{
            background: #111122;
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid #1e1e2e;
        }}
        .stat-value {{ font-size: 1.2rem; font-weight: 700; color: #a78bfa; }}
        .stat-label {{ font-size: 0.75rem; color: #6b7280; }}
    </style>
</head>
<body>
    <h1>📡 Timeline — {session_name}</h1>
    <div class="stats" id="stats"></div>
    <div class="controls">
        <input type="text" id="filter" placeholder="Filter by URL or text..." />
        <select id="directionFilter">
            <option value="">All Directions</option>
            <option value="SENT">Sent</option>
            <option value="RECEIVED">Received</option>
        </select>
        <select id="protocolFilter">
            <option value="">All Protocols</option>
        </select>
    </div>
    <div class="timeline" id="timeline"></div>

    <script>
    const events = {events_json};

    function init() {{
        // Build stats
        const statsEl = document.getElementById('stats');
        const totalFrames = events.filter(e => e.type === 'frame').length;
        const sent = events.filter(e => e.direction === 'SENT').length;
        const received = events.filter(e => e.direction === 'RECEIVED').length;
        const annotations = events.filter(e => e.type === 'annotation').length;
        statsEl.innerHTML = `
            <div class="stat"><div class="stat-value">${{totalFrames}}</div><div class="stat-label">Total Frames</div></div>
            <div class="stat"><div class="stat-value">${{sent}}</div><div class="stat-label">Sent</div></div>
            <div class="stat"><div class="stat-value">${{received}}</div><div class="stat-label">Received</div></div>
            <div class="stat"><div class="stat-value">${{annotations}}</div><div class="stat-label">Annotations</div></div>
        `;

        // Build protocol filter
        const protocols = [...new Set(events.filter(e => e.protocol).map(e => e.protocol))];
        const protocolFilter = document.getElementById('protocolFilter');
        protocols.forEach(p => {{
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            protocolFilter.appendChild(opt);
        }});

        // Add filter listeners
        document.getElementById('filter').addEventListener('input', render);
        document.getElementById('directionFilter').addEventListener('change', render);
        document.getElementById('protocolFilter').addEventListener('change', render);

        render();
    }}

    function render() {{
        const filter = document.getElementById('filter').value.toLowerCase();
        const dirFilter = document.getElementById('directionFilter').value;
        const protoFilter = document.getElementById('protocolFilter').value;

        const filtered = events.filter(e => {{
            if (filter && !(e.url || '').toLowerCase().includes(filter)
                && !(e.text || '').toLowerCase().includes(filter)) return false;
            if (dirFilter && e.direction !== dirFilter) return false;
            if (protoFilter && e.protocol !== protoFilter) return false;
            return true;
        }});

        const timeline = document.getElementById('timeline');
        const displayed = filtered.slice(0, 500);
        timeline.innerHTML = displayed.map(e => {{
            if (e.type === 'annotation') {{
                return `<div class="event annotation">
                    <span class="time">${{new Date(e.time).toLocaleTimeString()}}</span>
                    <span class="annotation-text">📌 ${{e.text}}</span>
                </div>`;
            }}
            return `<div class="event ${{e.direction.toLowerCase()}}">
                <span class="time">${{new Date(e.time).toLocaleTimeString()}}</span>
                <span class="direction ${{e.direction.toLowerCase()}}">${{e.direction}}</span>
                <span class="protocol-badge protocol-${{e.protocol}}">${{e.protocol}}</span>
                <span class="url">${{(e.url || '').substring(0, 100)}}</span>
            </div>`;
        }}).join('');

        if (filtered.length > 500) {{
            timeline.innerHTML += `<div class="event" style="text-align:center;color:#6b7280;">
                ... ${{filtered.length - 500}} more events
            </div>`;
        }}
    }}

    init();
    </script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path
