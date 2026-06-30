"""Interactive HTML binary packet explorer.

Generates a standalone, feature-rich HTML interface containing hex views,
byte stability grids, candidate prices, and family classifications.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from wiretap.analysis.classification import BinaryPacketFamily, BinaryPacketFingerprint
from wiretap.analysis.structural import FieldMapEntry
from wiretap.analysis.similarity import PriceCandidate
from wiretap.analysis.correlation import CorrelationResult
from wiretap.analysis.protocol_graph import StateTransition, RequestResponseChain
from wiretap.core.models import Connection, Frame, Payload


def generate_packet_explorer(
    output_path: Path,
    session_name: str,
    families: list[BinaryPacketFamily],
    field_maps: dict[str, list[FieldMapEntry]],
    price_candidates: dict[str, list[PriceCandidate]],
    correlations: list[CorrelationResult],
    transitions: list[StateTransition],
    chains: list[RequestResponseChain],
    connections: list[Connection],
    frames: list[Frame],
    payloads: dict[UUID, Payload],
) -> Path:
    """Generate the premium Wireshark-like Packet Explorer HTML report."""
    conn_map = {str(c.id): c for c in connections}

    # Prepare packets list for JS
    packets_data = []
    for frame in sorted(frames, key=lambda f: f.timestamp):
        if not frame.payload_id or frame.payload_id not in payloads:
            continue
        payload = payloads[frame.payload_id]
        conn = conn_map.get(str(frame.connection_id))

        # Associate to family
        family_id = "unknown"
        for fam in families:
            if any(fp.frame_id == frame.id for fp in fam.fingerprints):
                family_id = fam.id
                break

        # Decode previews
        text_preview = ""
        try:
            text_preview = payload.raw_bytes[:2000].decode("utf-8", errors="replace")
        except Exception:
            text_preview = "(binary data)"

        packets_data.append({
            "id": str(frame.id),
            "timestamp": frame.timestamp.isoformat(),
            "direction": frame.direction.name,
            "url": conn.url if conn else "",
            "protocol": conn.protocol.name if conn else "",
            "size": payload.size,
            "sha256": payload.sha256,
            "family_id": family_id,
            "hex": payload.raw_bytes[:1024].hex(),
            "text": text_preview,
            "is_binary": frame.is_binary,
        })

    # Prepare families metadata
    families_data = []
    for fam in families:
        # Get field map for family
        f_map = field_maps.get(fam.id, [])
        f_map_json = [
            {
                "offset": entry.offset,
                "size": entry.size,
                "stability": entry.stability,
                "type_name": entry.type_name,
                "description": entry.description,
                "sample_values": entry.sample_values,
            }
            for entry in f_map
        ]

        # Get price candidates
        p_cands = price_candidates.get(fam.id, [])
        p_cands_json = [
            {
                "offset": cand.offset,
                "size": cand.size,
                "endianness": cand.endianness,
                "value_type": cand.value_type,
                "scale_factor": cand.scale_factor,
                "sample_values": cand.sample_values,
                "confidence": cand.confidence,
                "description": cand.description,
            }
            for cand in p_cands
        ]

        families_data.append({
            "id": fam.id,
            "direction": fam.direction.name,
            "common_prefix": fam.common_prefix,
            "avg_length": int(fam.avg_length),
            "count": fam.count,
            "avg_interval": f"{fam.avg_interval:.2f}s",
            "entropy": f"{fam.entropy:.2f}",
            "confidence": f"{fam.confidence * 100:.0f}%",
            "likely_purpose": fam.likely_purpose,
            "field_map": f_map_json,
            "price_candidates": p_cands_json,
        })

    # Correlations
    correlations_data = [
        {
            "action_text": c.action_text,
            "family_id": c.family_id,
            "co_occurrences": c.co_occurrences,
            "total_actions": c.total_actions,
            "total_family_count": c.total_family_count,
            "probability": f"{c.probability * 100:.1f}%",
            "lift": f"{c.lift:.1f}x",
            "confidence": f"{c.confidence * 100:.0f}%",
            "description": c.description,
        }
        for c in correlations
    ]

    # Inferred chains
    chains_data = [
        {
            "request_family": ch.request_family,
            "response_family": ch.response_family,
            "match_count": ch.match_count,
            "total_requests": ch.total_requests,
            "avg_latency_ms": int(ch.avg_latency * 1000),
            "confidence": f"{ch.confidence * 100:.0f}%",
            "description": ch.description,
        }
        for ch in chains
    ]

    # Transitions
    transitions_data = [
        {
            "from_family": t.from_family,
            "to_family": t.to_family,
            "count": t.count,
            "avg_interval": f"{t.avg_interval:.2f}s",
            "probability": f"{t.probability * 100:.1f}%",
        }
        for t in transitions
    ]
    # Serialize to JSON strings for embedding in template
    packets_json = json.dumps(packets_data)
    families_json = json.dumps(families_data)
    correlations_json = json.dumps(correlations_data)
    transitions_json = json.dumps(transitions_data)
    chains_json = json.dumps(chains_data)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wiretap Binary Packet Explorer — {session_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: #09090e;
            color: #d1d5db;
            display: grid;
            grid-template-columns: 280px 1fr;
            grid-template-rows: 60px 1fr;
            height: 100vh;
            overflow: hidden;
        }}
        
        /* Layout */
        header {{
            grid-column: 1 / -1;
            background: #11111a;
            border-bottom: 1px solid #1e1e2f;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
        }}
        header h1 {{
            font-size: 1.2rem;
            font-weight: 600;
            color: #a78bfa;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .header-stats {{
            display: flex;
            gap: 24px;
            font-size: 0.8rem;
        }}
        .stat-badge {{
            background: #1a1a2e;
            border: 1px solid #2e2e4f;
            border-radius: 4px;
            padding: 4px 10px;
            color: #c084fc;
        }}
        
        .sidebar {{
            background: #0c0c14;
            border-right: 1px solid #1e1e2f;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            overflow-y: auto;
        }}
        .sidebar-section h3 {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #6b7280;
            margin-bottom: 8px;
        }}
        
        .nav-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .nav-item {{
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.15s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .nav-item:hover {{ background: #1a1a2e; color: #a78bfa; }}
        .nav-item.active {{ background: #231f47; color: #c084fc; font-weight: 500; }}
        .nav-item .badge {{
            background: #2e2e4f;
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 0.7rem;
            color: #9ca3af;
        }}
        
        main {{
            display: grid;
            grid-template-columns: 1fr 380px;
            height: 100%;
            overflow: hidden;
        }}
        
        .content-panel {{
            display: flex;
            flex-direction: column;
            overflow: hidden;
            border-right: 1px solid #1e1e2f;
        }}
        
        .search-bar {{
            padding: 12px 16px;
            background: #11111a;
            border-bottom: 1px solid #1e1e2f;
            display: flex;
            gap: 12px;
        }}
        .search-bar input {{
            flex: 1;
            background: #09090e;
            border: 1px solid #2e2e4f;
            color: #e5e7eb;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
        }}
        .search-bar input:focus {{
            outline: none;
            border-color: #a78bfa;
        }}
        
        /* Table / list styling */
        .packets-table-container {{
            flex: 1;
            overflow-y: auto;
        }}
        .packets-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
            text-align: left;
        }}
        .packets-table th {{
            background: #11111a;
            color: #9ca3af;
            font-weight: 500;
            padding: 10px 16px;
            border-bottom: 1px solid #1e1e2f;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        .packets-table td {{
            padding: 10px 16px;
            border-bottom: 1px solid #131320;
            cursor: pointer;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .packets-table tr:hover {{ background: #131322; }}
        .packets-table tr.selected {{ background: #1b163d; }}
        
        .direction-sent {{ color: #fbbf24; }}
        .direction-received {{ color: #3b82f6; }}
        
        /* Inspector / Detail side panel */
        .inspector-panel {{
            background: #0a0a0f;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            padding: 16px;
            gap: 20px;
        }}
        .inspector-section h3 {{
            font-size: 0.8rem;
            color: #a78bfa;
            border-bottom: 1px solid #2e2e4f;
            padding-bottom: 6px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 8px;
            font-size: 0.8rem;
        }}
        .meta-label {{ color: #6b7280; }}
        .meta-val {{ word-break: break-all; font-family: 'JetBrains Mono', monospace; }}
        
        /* Byte Stability Grid */
        .stability-grid {{
            display: grid;
            grid-template-columns: repeat(8, 1fr);
            gap: 4px;
            margin-bottom: 12px;
        }}
        .stability-cell {{
            aspect-ratio: 1;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.65rem;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            cursor: help;
        }}
        .stability-cell.constant {{ background: #10b981; color: #042f1a; }}
        .stability-cell.variable {{ background: #ef4444; color: #490e0e; }}
        .stability-cell.counter {{ background: #3b82f6; color: #08214d; }}
        .stability-cell.float {{ background: #a78bfa; color: #2e1065; }}
        .stability-cell.timestamp {{ background: #ec4899; color: #500724; }}
        
        /* Legends */
        .legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            font-size: 0.7rem;
            margin-top: 8px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 4px;
        }}
        .legend-dot {{
            width: 8px;
            height: 8px;
            border-radius: 2px;
        }}
        
        /* Hex view */
        .hex-viewer {{
            background: #050508;
            border: 1px solid #1e1e2f;
            border-radius: 6px;
            padding: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.72rem;
            white-space: pre;
            overflow-x: auto;
            line-height: 1.4;
            max-height: 300px;
        }}
        
        /* Info view */
        .panel-empty {{
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #6b7280;
            font-size: 0.85rem;
        }}
        
        /* Tabs for main content view */
        .tabs-header {{
            display: flex;
            background: #11111a;
            border-bottom: 1px solid #1e1e2f;
        }}
        .tab-button {{
            padding: 12px 20px;
            font-size: 0.85rem;
            color: #9ca3af;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.15s;
        }}
        .tab-button:hover {{ color: #e5e7eb; background: #161622; }}
        .tab-button.active {{
            color: #a78bfa;
            border-bottom-color: #a78bfa;
            font-weight: 500;
            background: #161622;
        }}
        
        .tab-content-pane {{
            display: none;
            height: 100%;
            overflow: hidden;
        }}
        .tab-content-pane.active {{
            display: flex;
            flex-direction: column;
        }}

        /* Scrollbars */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: #09090e;
        }}
        ::-webkit-scrollbar-thumb {{
            background: #1e1e2f;
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #2a2a3f;
        }}
        
        /* Price candidates listing styling */
        .price-candidate-card {{
            background: #11111a;
            border: 1px solid #2e2e4f;
            border-radius: 6px;
            padding: 8px 12px;
            margin-bottom: 8px;
            font-size: 0.78rem;
        }}
        .price-candidate-card .badge {{
            float: right;
            background: #4c1d95;
            color: #c084fc;
            padding: 1px 6px;
            border-radius: 4px;
            font-size: 0.65rem;
        }}
        
        /* Correlation Cards */
        .correlation-card {{
            background: #11111a;
            border-left: 3px solid #ec4899;
            padding: 8px 12px;
            border-radius: 0 6px 6px 0;
            font-size: 0.78rem;
            margin-bottom: 8px;
        }}
    </style>
</head>
<body>

    <header>
        <h1>🔍 Wiretap Protocol Explorer</h1>
        <div class="header-stats">
            <span class="stat-badge">Families: <strong id="stat-families-count">0</strong></span>
            <span class="stat-badge">Frames: <strong id="stat-frames-count">0</strong></span>
            <span class="stat-badge">Inferred Chains: <strong id="stat-chains-count">0</strong></span>
        </div>
    </header>

    <div class="sidebar">
        <div class="sidebar-section">
            <h3>Navigation</h3>
            <ul class="nav-list">
                <li class="nav-item active" onclick="switchNav('packets')">
                    <span>Packets Timeline</span>
                </li>
                <li class="nav-item" onclick="switchNav('families')">
                    <span>Packet Families</span>
                    <span class="badge" id="nav-families-badge">0</span>
                </li>
                <li class="nav-item" onclick="switchNav('relationships')">
                    <span>Transitions & Chains</span>
                </li>
                <li class="nav-item" onclick="switchNav('correlations')">
                    <span>Action Correlations</span>
                </li>
            </ul>
        </div>
    </div>

    <main>
        <!-- Center panel containing lists/grids -->
        <div class="content-panel">
            
            <!-- Packet Timeline Nav View -->
            <div id="view-packets" class="tab-content-pane active">
                <div class="search-bar">
                    <input type="text" id="packets-search" placeholder="Filter packets by hex, size, protocol, or family ID..." oninput="filterPackets()">
                </div>
                <div class="packets-table-container">
                    <table class="packets-table">
                        <thead>
                            <tr>
                                <th style="width: 60px;">Index</th>
                                <th style="width: 100px;">Direction</th>
                                <th style="width: 80px;">Protocol</th>
                                <th style="width: 70px;">Size</th>
                                <th style="width: 150px;">Family</th>
                                <th>Payload Preview</th>
                            </tr>
                        </thead>
                        <tbody id="packets-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Packet Families Nav View -->
            <div id="view-families" class="tab-content-pane">
                <div class="packets-table-container">
                    <table class="packets-table">
                        <thead>
                            <tr>
                                <th>Family ID</th>
                                <th>Direction</th>
                                <th>Count</th>
                                <th>Avg Length</th>
                                <th>Interval</th>
                                <th>Entropy</th>
                                <th>Confidence</th>
                                <th>Likely Purpose</th>
                            </tr>
                        </thead>
                        <tbody id="families-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Transitions & Chains View -->
            <div id="view-relationships" class="tab-content-pane" style="padding: 16px; overflow-y: auto; gap: 20px;">
                <div>
                    <h2 style="font-size: 1rem; color: #a78bfa; margin-bottom: 12px; border-bottom: 1px solid #1e1e2f; padding-bottom: 6px;">🔗 Inferred Request-Response Chains</h2>
                    <div id="chains-container" style="display: flex; flex-direction: column; gap: 8px;"></div>
                </div>
                <div>
                    <h2 style="font-size: 1rem; color: #a78bfa; margin-bottom: 12px; border-bottom: 1px solid #1e1e2f; padding-bottom: 6px;">🔄 State Transitions Matrix</h2>
                    <table class="packets-table">
                        <thead>
                            <tr>
                                <th>From Family</th>
                                <th>To Family</th>
                                <th>Transition Count</th>
                                <th>Avg Delay</th>
                                <th>Probability</th>
                            </tr>
                        </thead>
                        <tbody id="transitions-tbody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Correlations View -->
            <div id="view-correlations" class="tab-content-pane" style="padding: 16px; overflow-y: auto;">
                <h2 style="font-size: 1rem; color: #a78bfa; margin-bottom: 12px; border-bottom: 1px solid #1e1e2f; padding-bottom: 6px;">⚡ User Annotation timeline Correlations</h2>
                <div id="correlations-container" style="display: flex; flex-direction: column; gap: 8px;"></div>
            </div>

        </div>

        <!-- Right detail inspector panel -->
        <div class="inspector-panel" id="inspector-container">
            <div class="panel-empty" id="inspector-placeholder">
                Select an item to view structural details
            </div>
            <div id="inspector-content" style="display: none;">
                <div class="inspector-section">
                    <h3>📋 Frame Metadata</h3>
                    <div class="meta-grid">
                        <span class="meta-label">Frame ID</span><span class="meta-val" id="meta-frame-id">-</span>
                        <span class="meta-label">Timestamp</span><span class="meta-val" id="meta-timestamp">-</span>
                        <span class="meta-label">Protocol</span><span class="meta-val" id="meta-protocol">-</span>
                        <span class="meta-label">Direction</span><span class="meta-val" id="meta-direction">-</span>
                        <span class="meta-label">Size</span><span class="meta-val" id="meta-size">-</span>
                        <span class="meta-label">SHA256</span><span class="meta-val" id="meta-sha256">-</span>
                        <span class="meta-label">Family ID</span><span class="meta-val" id="meta-family-id">-</span>
                    </div>
                </div>

                <div class="inspector-section" id="inspector-sec-stability" style="display: none;">
                    <h3>📊 Byte Stability Map</h3>
                    <div class="stability-grid" id="stability-grid-container"></div>
                    <div class="legend">
                        <div class="legend-item"><div class="legend-dot constant"></div> Constant</div>
                        <div class="legend-item"><div class="legend-dot variable"></div> Variable</div>
                        <div class="legend-item"><div class="legend-dot counter"></div> Counter</div>
                        <div class="legend-item"><div class="legend-dot float"></div> Float</div>
                        <div class="legend-item"><div class="legend-dot timestamp"></div> Timestamp</div>
                    </div>
                </div>

                <div class="inspector-section" id="inspector-sec-prices" style="display: none;">
                    <h3>🏷️ Candidate Price Fields</h3>
                    <div id="inspector-prices-container"></div>
                </div>

                <div class="inspector-section">
                    <h3>🔢 Hex View (First 512B)</h3>
                    <div class="hex-viewer" id="hex-viewer-container"></div>
                </div>

                <div class="inspector-section">
                    <h3>📝 ASCII Preview</h3>
                    <div class="hex-viewer" id="text-viewer-container" style="white-space: pre-wrap; word-break: break-all;"></div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const packets = {packets_json};
        const families = {families_json};
        const correlations = {correlations_json};
        const chains = {chains_json};
        const transitions = {transitions_json};

        let selectedPacketIndex = -1;
        let selectedFamilyId = "";

        // Initialize lists
        document.getElementById('stat-families-count').innerText = families.length;
        document.getElementById('stat-frames-count').innerText = packets.length;
        document.getElementById('stat-chains-count').innerText = chains.length;
        document.getElementById('nav-families-badge').innerText = families.length;

        function switchNav(nav) {{
            // Deactivate all
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-content-pane').forEach(el => el.classList.remove('active'));

            // Activate chosen
            let navIndex = 0;
            if (nav === 'packets') navIndex = 0;
            else if (nav === 'families') navIndex = 1;
            else if (nav === 'relationships') navIndex = 2;
            else if (nav === 'correlations') navIndex = 3;

            document.querySelectorAll('.nav-item')[navIndex].classList.add('active');
            document.getElementById('view-' + nav).classList.add('active');
        }}

        function populatePackets() {{
            const tbody = document.getElementById('packets-tbody');
            tbody.innerHTML = packets.map((p, i) => {{
                const dirClass = p.direction === 'SENT' ? 'direction-sent' : 'direction-received';
                const preview = p.hex.substring(0, 80) + '...';
                return `<tr id="packet-tr-${{i}}" onclick="selectPacket(${{i}})">
                    <td>${{i}}</td>
                    <td class="${{dirClass}}">${{p.direction}}</td>
                    <td>${{p.protocol}}</td>
                    <td>${{p.size}} B</td>
                    <td style="color:#a78bfa; font-family:'JetBrains Mono', monospace;">${{p.family_id}}</td>
                    <td style="font-family:'JetBrains Mono', monospace; color:#9ca3af;">${{preview}}</td>
                </tr>`;
            }}).join('');
        }}

        function populateFamilies() {{
            const tbody = document.getElementById('families-tbody');
            tbody.innerHTML = families.map((f) => {{
                return `<tr onclick="selectFamily('${{f.id}}')">
                    <td style="color:#a78bfa; font-weight:500; font-family:'JetBrains Mono', monospace;">${{f.id}}</td>
                    <td class="${{f.direction === 'SENT' ? 'direction-sent' : 'direction-received'}}">${{f.direction}}</td>
                    <td>${{f.count}}</td>
                    <td>${{f.avg_length}} B</td>
                    <td>${{f.avg_interval}}</td>
                    <td>${{f.entropy}}</td>
                    <td style="color:#c084fc;">${{f.confidence}}</td>
                    <td style="color:#e5e7eb;">${{f.likely_purpose}}</td>
                </tr>`;
            }}).join('');
        }}

        function populateRelationships() {{
            // Chains
            const chainsContainer = document.getElementById('chains-container');
            if (chains.length === 0) {{
                chainsContainer.innerHTML = '<div style="color:#6b7280; font-size:0.8rem;">No request-response chains detected.</div>';
            }} else {{
                chainsContainer.innerHTML = chains.map(c => {{
                    return `<div class="price-candidate-card" style="border-left: 3px solid #3b82f6;">
                        <span class="badge" style="background:#1e3a8a; color:#93c5fd;">${{c.confidence}} confidence</span>
                        <div style="font-weight:600; margin-bottom:4px; font-family:'JetBrains Mono', monospace; color:#a78bfa;">
                            ${{c.request_family}} &rarr; ${{c.response_family}}
                        </div>
                        <div style="color:#9ca3af; font-size:0.75rem;">${{c.description}}</div>
                    </div>`;
                }}).join('');
            }}

            // Transitions
            const transBody = document.getElementById('transitions-tbody');
            transBody.innerHTML = transitions.map(t => {{
                return `<tr>
                    <td style="font-family:'JetBrains Mono', monospace;">${{t.from_family}}</td>
                    <td style="font-family:'JetBrains Mono', monospace;">${{t.to_family}}</td>
                    <td>${{t.count}}</td>
                    <td>${{t.avg_interval}}</td>
                    <td style="color:#c084fc; font-weight:500;">${{t.probability}}</td>
                </tr>`;
            }}).join('');
        }}

        function populateCorrelations() {{
            const corrContainer = document.getElementById('correlations-container');
            if (correlations.length === 0) {{
                corrContainer.innerHTML = '<div style="color:#6b7280; font-size:0.8rem;">No timeline annotations available for correlation.</div>';
            }} else {{
                corrContainer.innerHTML = correlations.map(c => {{
                    return `<div class="correlation-card">
                        <div style="font-weight:600; margin-bottom:4px; color:#f43f5e;">
                            Action: "${{c.action_text}}"
                        </div>
                        <div style="color:#e5e7eb; font-size:0.78rem; font-family:'JetBrains Mono', monospace; margin-bottom:4px;">
                            Correlated Family: ${{c.family_id}} (Confidence: ${{c.confidence}})
                        </div>
                        <div style="color:#9ca3af; font-size:0.75rem;">${{c.description}}</div>
                    </div>`;
                }}).join('');
            }}
        }}

        function selectPacket(index) {{
            // Manage UI highlights
            if (selectedPacketIndex !== -1) {{
                const el = document.getElementById('packet-tr-' + selectedPacketIndex);
                if (el) el.classList.remove('selected');
            }}
            selectedPacketIndex = index;
            document.getElementById('packet-tr-' + index).classList.add('selected');

            const p = packets[index];
            showInspector(p);
        }}

        function selectFamily(id) {{
            selectedFamilyId = id;
            // Find a packet of this family to showcase hex representation
            const p = packets.find(pk => pk.family_id === id);
            if (p) {{
                showInspector(p);
            }}
        }}

        function showInspector(p) {{
            document.getElementById('inspector-placeholder').style.display = 'none';
            document.getElementById('inspector-content').style.display = 'block';

            // Populate metadata
            document.getElementById('meta-frame-id').innerText = p.id;
            document.getElementById('meta-timestamp').innerText = p.timestamp;
            document.getElementById('meta-protocol').innerText = p.protocol;
            document.getElementById('meta-direction').innerText = p.direction;
            document.getElementById('meta-size').innerText = p.size + ' Bytes';
            document.getElementById('meta-sha256').innerText = p.sha256.substring(0, 16) + '...';
            document.getElementById('meta-family-id').innerText = p.family_id;

            // Hex and ASCII viewers
            document.getElementById('hex-viewer-container').innerText = formatHex(p.hex);
            document.getElementById('text-viewer-container').innerText = p.text;

            // Locate family structural information
            const fam = families.find(f => f.id === p.family_id);
            if (fam) {{
                // Stability Grid
                document.getElementById('inspector-sec-stability').style.display = 'block';
                const gridContainer = document.getElementById('stability-grid-container');
                gridContainer.innerHTML = '';
                
                let currentOffset = 0;
                fam.field_map.forEach(entry => {{
                    for (let s = 0; s < entry.size; s++) {{
                        const cell = document.createElement('div');
                        cell.className = 'stability-cell ' + entry.stability;
                        cell.innerText = (currentOffset).toString(16).padStart(2, '0');
                        cell.title = `Offset 0x${{currentOffset.toString(16)}} (${{currentOffset}})\\nType: ${{entry.type_name}}\\nStability: ${{entry.stability}}\\nDescription: ${{entry.description}}\\nSample: ${{entry.sample_values.join(', ')}}`;
                        gridContainer.appendChild(cell);
                        currentOffset++;
                    }}
                }});

                // Price Candidates
                const priceSec = document.getElementById('inspector-sec-prices');
                const priceContainer = document.getElementById('inspector-prices-container');
                if (fam.price_candidates && fam.price_candidates.length > 0) {{
                    priceSec.style.display = 'block';
                    priceContainer.innerHTML = fam.price_candidates.map(c => {{
                        return `<div class="price-candidate-card">
                            <span class="badge">${{Math.round(c.confidence * 100)}}% Match</span>
                            <div style="font-weight:600; color:#a78bfa; margin-bottom:2px;">
                                Offset 0x${{c.offset.toString(16)}} (${{c.offset}}) &bull; ${{c.value_type}}
                            </div>
                            <div style="color:#e5e7eb; font-family:'JetBrains Mono', monospace; font-size:0.75rem; margin-bottom:4px;">
                                Candidate Values: ${{c.sample_values.map(v => v.toFixed(4)).join(', ')}}
                            </div>
                            <div style="color:#6b7280; font-size:0.7rem;">${{c.description}}</div>
                        </div>`;
                    }}).join('');
                }} else {{
                    priceSec.style.display = 'none';
                }}
            }} else {{
                document.getElementById('inspector-sec-stability').style.display = 'none';
                document.getElementById('inspector-sec-prices').style.display = 'none';
            }}
        }}

        function filterPackets() {{
            const query = document.getElementById('packets-search').value.toLowerCase();
            const rows = document.getElementById('packets-tbody').getElementsByTagName('tr');

            for (let i = 0; i < rows.length; i++) {{
                const text = rows[i].textContent.toLowerCase();
                if (text.includes(query)) {{
                    rows[i].style.display = '';
                }} else {{
                    rows[i].style.display = 'none';
                }}
            }}
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

        // Run
        populatePackets();
        populateFamilies();
        populateRelationships();
        populateCorrelations();
    </script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content)
    return output_path
