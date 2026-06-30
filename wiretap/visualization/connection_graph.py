"""Interactive HTML connection graph visualization.

Generates a standalone HTML file showing the browser's connections
to various services and endpoints as an interactive node graph.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from wiretap.core.models import Connection


def generate_connection_graph(
    output_path: Path,
    connections: list[Connection],
    session_name: str = "Capture Session",
) -> Path:
    """Generate an interactive HTML connection graph.

    Args:
        output_path: Path to write the HTML file.
        connections: All connections in the session.
        session_name: Title for the graph.

    Returns:
        Path to the generated HTML file.
    """
    # Build graph data — group connections by domain
    domain_counter: Counter[str] = Counter()
    domain_protocols: dict[str, set[str]] = {}

    for conn in connections:
        try:
            parsed = urlparse(conn.url)
            domain = parsed.netloc or conn.url[:50]
        except Exception:
            domain = conn.url[:50]

        domain_counter[domain] += 1
        if domain not in domain_protocols:
            domain_protocols[domain] = set()
        domain_protocols[domain].add(conn.protocol.name)

    nodes = [{"id": "browser", "label": "Browser", "type": "browser", "size": 30}]
    edges = []

    for domain, count in domain_counter.most_common(50):
        protocols = list(domain_protocols.get(domain, set()))
        nodes.append({
            "id": domain,
            "label": domain,
            "type": protocols[0].lower() if protocols else "http",
            "size": min(10 + count * 2, 40),
            "count": count,
            "protocols": protocols,
        })
        edges.append({
            "source": "browser",
            "target": domain,
            "weight": count,
        })

    nodes_json = json.dumps(nodes, indent=2)
    edges_json = json.dumps(edges, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Connection Graph — {session_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e8;
            overflow: hidden;
        }}
        h1 {{
            position: fixed;
            top: 16px;
            left: 24px;
            font-size: 1.2rem;
            color: #a78bfa;
            z-index: 10;
        }}
        canvas {{ display: block; }}
        .legend {{
            position: fixed;
            bottom: 16px;
            right: 16px;
            background: rgba(17, 17, 34, 0.9);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid #1e1e2e;
            font-size: 0.75rem;
            z-index: 10;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }}
        .legend-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }}
        .tooltip {{
            position: fixed;
            display: none;
            background: rgba(17, 17, 34, 0.95);
            border: 1px solid #a78bfa;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            z-index: 20;
            pointer-events: none;
        }}
    </style>
</head>
<body>
    <h1>🔗 Connection Graph — {session_name}</h1>
    <canvas id="graph"></canvas>
    <div class="tooltip" id="tooltip"></div>
    <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:#a78bfa"></div> Browser</div>
        <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div> HTTP</div>
        <div class="legend-item"><div class="legend-dot" style="background:#10b981"></div> WebSocket</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div> SSE</div>
        <div class="legend-item"><div class="legend-dot" style="background:#c084fc"></div> Fetch/XHR</div>
    </div>

    <script>
    const nodes = {nodes_json};
    const edges = {edges_json};

    const canvas = document.getElementById('graph');
    const ctx = canvas.getContext('2d');
    const tooltip = document.getElementById('tooltip');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const colors = {{
        browser: '#a78bfa',
        http: '#3b82f6',
        websocket: '#10b981',
        sse: '#f59e0b',
        fetch: '#c084fc',
        xhr: '#c084fc',
    }};

    // Position nodes in a radial layout
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    nodes[0].x = cx;
    nodes[0].y = cy;

    const radius = Math.min(cx, cy) * 0.6;
    for (let i = 1; i < nodes.length; i++) {{
        const angle = (2 * Math.PI * (i - 1)) / (nodes.length - 1);
        nodes[i].x = cx + radius * Math.cos(angle);
        nodes[i].y = cy + radius * Math.sin(angle);
    }}

    function draw() {{
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Draw edges
        edges.forEach(edge => {{
            const src = nodes.find(n => n.id === edge.source);
            const tgt = nodes.find(n => n.id === edge.target);
            if (!src || !tgt) return;

            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.strokeStyle = `rgba(167, 139, 250, ${{Math.min(0.1 + edge.weight * 0.05, 0.5)}})`;
            ctx.lineWidth = Math.min(1 + edge.weight * 0.3, 5);
            ctx.stroke();
        }});

        // Draw nodes
        nodes.forEach(node => {{
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.size / 2, 0, Math.PI * 2);
            const color = colors[node.type] || colors.http;
            ctx.fillStyle = color;
            ctx.globalAlpha = 0.8;
            ctx.fill();
            ctx.globalAlpha = 1;
            ctx.strokeStyle = color;
            ctx.lineWidth = 2;
            ctx.stroke();

            // Label
            ctx.fillStyle = '#e0e0e8';
            ctx.font = '11px Inter, sans-serif';
            ctx.textAlign = 'center';
            const label = node.label.length > 30 ? node.label.substring(0, 30) + '...' : node.label;
            ctx.fillText(label, node.x, node.y + node.size / 2 + 14);
        }});
    }}

    // Hover tooltip
    canvas.addEventListener('mousemove', (e) => {{
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;

        let found = null;
        nodes.forEach(node => {{
            const dx = mx - node.x;
            const dy = my - node.y;
            if (Math.sqrt(dx * dx + dy * dy) < node.size / 2 + 5) found = node;
        }});

        if (found && found.id !== 'browser') {{
            tooltip.style.display = 'block';
            tooltip.style.left = (e.clientX + 12) + 'px';
            tooltip.style.top = (e.clientY + 12) + 'px';
            tooltip.innerHTML = `<strong>${{found.label}}</strong><br>
                Connections: ${{found.count || 1}}<br>
                Protocols: ${{(found.protocols || []).join(', ')}}`;
        }} else {{
            tooltip.style.display = 'none';
        }}
    }});

    window.addEventListener('resize', () => {{
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        draw();
    }});

    draw();
    </script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path
