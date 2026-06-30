"""Wiretap CLI — Professional browser protocol analysis framework.

Commands:
    wiretap capture <url>     Start a capture session
    wiretap analyze <session> Run protocol discovery
    wiretap inspect <session> Interactive frame inspector
    wiretap replay <session>  Replay session frame-by-frame
    wiretap report <session>  Generate reports
    wiretap decode <data>     Decode a payload
    wiretap compare <a> <b>   Compare two sessions
    wiretap stats <session>   Show statistics
    wiretap plugins           List installed plugins
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
from uuid import UUID

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from wiretap.core.config import BrowserConfig, WiretapConfig
from wiretap.core.logging import configure_logging

console = Console()
app = typer.Typer(
    name="wiretap",
    help="🔍 Wiretap — Professional browser protocol analysis framework",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _get_config(
    base_dir: Path | None = None,
    headless: bool = False,
    log_level: str = "INFO",
) -> WiretapConfig:
    """Build WiretapConfig from CLI options."""
    kwargs: dict = {}
    if base_dir:
        kwargs["base_dir"] = base_dir.resolve()
    kwargs["browser"] = BrowserConfig(headless=headless)
    kwargs["log_level"] = log_level
    config = WiretapConfig(**kwargs)
    config.ensure_directories()
    configure_logging(config.log_level, config.log_format)
    return config


async def _init_db(config: WiretapConfig):
    """Initialize database and return engine + session factory."""
    from wiretap.storage.engine import build_engine, build_session_factory, init_database

    engine = build_engine(config.database_path)
    await init_database(engine)
    session_factory = build_session_factory(engine)
    return engine, session_factory


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


@app.command()
def capture(
    url: str = typer.Argument(..., help="URL to navigate to and capture traffic from"),
    name: str = typer.Option("", "--name", "-n", help="Session name"),
    headless: bool = typer.Option(False, "--headless", help="Run browser in headless mode"),
    duration: int = typer.Option(0, "--duration", "-d", help="Auto-stop after N seconds (0 = manual)"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Browser profile name for persistent login"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir", help="Wiretap data directory"),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
) -> None:
    """🎯 Start a capture session — opens browser and records all traffic."""

    async def _run() -> None:
        config_kwargs: dict = {}
        if base_dir:
            config_kwargs["base_dir"] = base_dir.resolve()

        browser_kwargs: dict = {"headless": headless}
        if profile:
            profile_dir = (base_dir or Path.cwd()) / "profiles" / profile
            profile_dir.mkdir(parents=True, exist_ok=True)
            browser_kwargs["profile_dir"] = profile_dir

        config = WiretapConfig(
            browser=BrowserConfig(**browser_kwargs),
            log_level=log_level,
            **config_kwargs,
        )
        config.ensure_directories()
        configure_logging(config.log_level, config.log_format)

        engine, session_factory = await _init_db(config)

        from wiretap.core.events import EventBus
        from wiretap.capture.session import CaptureOrchestrator

        event_bus = EventBus()
        orchestrator = CaptureOrchestrator(config, session_factory, event_bus)

        console.print(Panel(
            f"[bold cyan]🔍 Wiretap Capture[/]\n\n"
            f"  Target: [bold]{url}[/]\n"
            f"  Mode: {'Headless' if headless else 'Headed'}\n"
            f"  Profile: {profile or 'Ephemeral'}\n"
            f"  Duration: {'Manual (Ctrl+C)' if not duration else f'{duration}s'}",
            border_style="cyan",
            box=box.ROUNDED,
        ))

        session_id = await orchestrator.start(url, name=name or url)
        console.print(f"\n[green]✓[/] Session started: [bold]{session_id}[/]")
        console.print("[dim]Press Ctrl+C to stop capture. Type annotations and press Enter.[/]\n")

        try:
            if duration > 0:
                await asyncio.sleep(duration)
            else:
                # Read annotations from stdin
                loop = asyncio.get_event_loop()
                while orchestrator.is_running:
                    try:
                        line = await asyncio.wait_for(
                            loop.run_in_executor(None, sys.stdin.readline),
                            timeout=1.0,
                        )
                        if line.strip():
                            await orchestrator.annotate(line.strip())
                            console.print(f"  [green]📌[/] Annotation: {line.strip()}")
                    except asyncio.TimeoutError:
                        continue
        except (KeyboardInterrupt, EOFError):
            pass

        session = await orchestrator.stop()
        if session:
            console.print(f"\n[green]✓[/] Capture complete: [bold]{session.id}[/]")

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    session_id: str = typer.Argument(..., help="Session ID to analyze"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """🔬 Run protocol discovery on a captured session."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import (
            ConnectionRepository, FrameRepository, PayloadRepository, SessionRepository,
        )
        from wiretap.analysis.discovery import ProtocolDiscovery
        from wiretap.decoders.registry import DecoderRegistry

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid)

            # Load payloads
            payloads = {}
            for f in frames:
                if f.payload_id:
                    p = await PayloadRepository.get(db, f.payload_id)
                    if p:
                        payloads[f.payload_id] = p

        # Decode payloads
        registry = DecoderRegistry()
        registry.discover()
        decoded = {}
        for pid, payload in payloads.items():
            result = registry.best_decode(payload.raw_bytes, payload.content_type)
            if result and result.data is not None:
                decoded[pid] = result.data

        # Run discovery
        discovery = ProtocolDiscovery()
        events = discovery.analyze(sid, connections, frames, payloads, decoded)

        # Display results
        console.print(Panel(
            f"[bold cyan]🔬 Protocol Analysis[/]\n\n"
            f"  Session: [bold]{session.name}[/]\n"
            f"  Connections: {len(connections)}\n"
            f"  Frames: {len(frames)}\n"
            f"  Events discovered: {len(events)}",
            border_style="cyan",
        ))

        if events:
            table = Table(title="Discovered Protocol Events", box=box.SIMPLE_HEAVY)
            table.add_column("Type", style="cyan")
            table.add_column("Confidence", justify="right")
            table.add_column("Description")
            table.add_column("Evidence", style="dim")

            for event in sorted(events, key=lambda e: e.confidence, reverse=True):
                table.add_row(
                    event.event_type.name,
                    f"{event.confidence:.0%}",
                    event.description,
                    "; ".join(event.evidence[:2]),
                )

            console.print(table)
        else:
            console.print("[yellow]No protocol events discovered.[/]")

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@app.command()
def stats(
    session_id: str = typer.Argument(..., help="Session ID"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """📊 Show statistics for a captured session."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import (
            ConnectionRepository, FrameRepository, PayloadRepository, SessionRepository,
        )
        from wiretap.analysis.statistics import StatisticsEngine
        from wiretap.utils.formatting import format_bytes, format_duration

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid)

            payloads = {}
            for f in frames:
                if f.payload_id:
                    p = await PayloadRepository.get(db, f.payload_id)
                    if p:
                        payloads[f.payload_id] = p

        engine_stats = StatisticsEngine()
        statistics = engine_stats.compute(
            connections, frames, payloads,
            session.started_at, session.ended_at,
        )

        # Display
        table = Table(title=f"Statistics: {session.name}", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        table.add_row("Total Connections", str(statistics.total_connections))
        table.add_row("Total Frames", str(statistics.total_frames))
        table.add_row("Frames Sent", str(statistics.frames_sent))
        table.add_row("Frames Received", str(statistics.frames_received))
        table.add_row("Total Bytes", format_bytes(statistics.total_bytes))
        table.add_row("Bytes Sent", format_bytes(statistics.bytes_sent))
        table.add_row("Bytes Received", format_bytes(statistics.bytes_received))
        table.add_row("Binary/Text Ratio", f"{statistics.binary_text_ratio:.2f}")
        table.add_row("Duration", format_duration(statistics.duration_seconds))
        table.add_row("Bandwidth", f"{format_bytes(int(statistics.bytes_per_second))}/s")
        table.add_row("Messages/sec", f"{statistics.messages_per_second:.1f}")

        console.print(table)

        if statistics.connections_by_protocol:
            proto_table = Table(title="Protocol Breakdown", box=box.SIMPLE)
            proto_table.add_column("Protocol", style="cyan")
            proto_table.add_column("Count", justify="right")
            proto_table.add_column("%", justify="right")
            for proto, count in statistics.connections_by_protocol.items():
                pct = statistics.protocol_breakdown.get(proto, 0)
                proto_table.add_row(proto, str(count), f"{pct}%")
            console.print(proto_table)

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """📝 Generate reports for a captured session."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import (
            AnnotationRepository, ConnectionRepository,
            FrameRepository, PayloadRepository, SessionRepository,
        )
        from wiretap.analysis.discovery import ProtocolDiscovery
        from wiretap.analysis.statistics import StatisticsEngine
        from wiretap.decoders.registry import DecoderRegistry
        from wiretap.reports.generator import ReportGenerator
        from wiretap.visualization.timeline import generate_timeline
        from wiretap.visualization.connection_graph import generate_connection_graph

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid)
            annotations = await AnnotationRepository.list_by_session(db, sid)

            payloads = {}
            for f in frames:
                if f.payload_id:
                    p = await PayloadRepository.get(db, f.payload_id)
                    if p:
                        payloads[f.payload_id] = p

        # Decode
        registry = DecoderRegistry()
        registry.discover()
        decoded = {}
        for pid, payload in payloads.items():
            result = registry.best_decode(payload.raw_bytes, payload.content_type)
            if result and result.data is not None:
                decoded[pid] = result.data

        # Analyze
        discovery = ProtocolDiscovery()
        events = discovery.analyze(sid, connections, frames, payloads, decoded)

        stats_engine = StatisticsEngine()
        statistics = stats_engine.compute(
            connections, frames, payloads,
            session.started_at, session.ended_at,
        )

        # Run binary protocol discovery (Phase 2)
        from wiretap.analysis.classification import BinaryClusteringEngine
        from wiretap.analysis.structural import StructuralAnalyzer
        from wiretap.analysis.similarity import PriceCandidateDetector
        from wiretap.analysis.correlation import BehaviorCorrelator
        from wiretap.analysis.protocol_graph import ProtocolGraphBuilder

        # Cluster binary packets
        binary_frames = [f for f in frames if f.is_binary and f.payload_id]
        binary_fps = []
        clustering_engine = BinaryClusteringEngine()

        for f in binary_frames:
            p = payloads.get(f.payload_id)
            if p:
                fp = clustering_engine.fingerprint_packet(
                    frame_id=f.id,
                    connection_id=f.connection_id,
                    direction=f.direction,
                    timestamp=f.timestamp,
                    payload_raw=p.raw_bytes,
                    sha256=p.sha256
                )
                binary_fps.append(fp)

        families = clustering_engine.cluster(binary_fps)

        structural_analyzer = StructuralAnalyzer()
        field_maps = {}
        for fam in families:
            field_maps[fam.id] = structural_analyzer.analyze_family(fam)

        price_detector = PriceCandidateDetector()
        price_candidates = {}
        for fam in families:
            price_candidates[fam.id] = price_detector.detect_prices(fam)

        correlator = BehaviorCorrelator()
        correlations = correlator.correlate(annotations, families, frames)

        graph_builder = ProtocolGraphBuilder()
        transitions = graph_builder.build_graph(families, frames)
        chains = graph_builder.infer_chains(families, frames)

        # Generate reports
        out_dir = output_dir or config.reports_dir / session_id
        generator = ReportGenerator(out_dir)
        generated = generator.generate_all(
            session, connections, frames, payloads,
            statistics, events, annotations,
        )

        # Generate Phase 2 reports
        binary_generated = generator.generate_binary_discovery(
            session, families, field_maps, price_candidates, correlations, transitions, chains,
            connections, frames, payloads
        )
        generated.extend(binary_generated)

        # Generate visualizations
        timeline_path = generate_timeline(
            out_dir / "timeline.html", connections, frames, annotations, session.name,
        )
        graph_path = generate_connection_graph(
            out_dir / "connection_graph.html", connections, session.name,
        )
        generated.extend([timeline_path, graph_path])

        console.print(Panel(
            f"[bold green]✓ Reports Generated[/]\n\n"
            + "\n".join(f"  📄 {p.name}" for p in generated),
            border_style="green",
        ))
        console.print(f"\n  Output: [bold]{out_dir}[/]")

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


@app.command()
def replay(
    session_id: str = typer.Argument(..., help="Session ID to replay"),
    filter_url: Optional[str] = typer.Option(None, "--filter", "-f", help="Filter by URL substring"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Filter by protocol (HTTP/WEBSOCKET/SSE)"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """▶️  Replay a captured session frame-by-frame."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import (
            ConnectionRepository, FrameRepository, PayloadRepository, SessionRepository,
        )
        from wiretap.protocols.replay import SessionReplay
        from wiretap.decoders.registry import DecoderRegistry
        from wiretap.core.enums import ProtocolType
        from wiretap.utils.formatting import format_bytes

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid)

            payloads = {}
            for f in frames:
                if f.payload_id:
                    p = await PayloadRepository.get(db, f.payload_id)
                    if p:
                        payloads[f.payload_id] = p

        registry = DecoderRegistry()
        registry.discover()

        replay_session = SessionReplay(connections, frames, payloads, registry)

        # Apply filters
        if protocol:
            proto = ProtocolType[protocol.upper()]
            replay_session.apply_filter(protocol=proto, url_contains=filter_url)
        elif filter_url:
            replay_session.apply_filter(url_contains=filter_url)

        console.print(Panel(
            f"[bold cyan]▶️  Session Replay[/]\n\n"
            f"  Session: [bold]{session.name}[/]\n"
            f"  Total frames: {replay_session.total_frames}\n\n"
            f"  [dim]Commands: n=next, p=prev, q=quit, g N=goto[/]",
            border_style="cyan",
        ))

        while True:
            try:
                cmd = input("\n[replay] > ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                break

            if cmd in ("q", "quit", "exit"):
                break
            elif cmd in ("n", "next", ""):
                info = replay_session.next()
                if info:
                    _print_frame_info(info)
                else:
                    console.print("[yellow]End of replay[/]")
            elif cmd in ("p", "prev"):
                info = replay_session.previous()
                if info:
                    _print_frame_info(info)
                else:
                    console.print("[yellow]Start of replay[/]")
            elif cmd.startswith("g "):
                try:
                    pos = int(cmd[2:])
                    info = replay_session.seek(pos)
                    if info:
                        _print_frame_info(info)
                    else:
                        console.print(f"[red]Invalid position: {pos}[/]")
                except ValueError:
                    console.print("[red]Usage: g <number>[/]")
            else:
                console.print("[dim]Commands: n=next, p=prev, q=quit, g N=goto[/]")

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


def _print_frame_info(info: dict) -> None:
    """Pretty-print frame info from replay."""
    conn = info.get("connection", {})
    payload = info.get("payload", {})
    dir_color = "yellow" if info["direction"] == "SENT" else "blue"

    header = (
        f"[{dir_color}]{info['direction']}[/{dir_color}] "
        f"[dim]#{info['position']}/{info['total']}[/dim] "
        f"[cyan]{conn.get('protocol', '')}[/cyan] "
        f"{conn.get('url', '')[:80]}"
    )
    console.print(header)

    if payload:
        from wiretap.utils.formatting import format_bytes
        console.print(f"  Size: {format_bytes(payload.get('size', 0))}  SHA256: {payload.get('sha256', '')[:16]}...")
        preview = payload.get("text_preview", "")
        if preview and preview != "(binary data)":
            console.print(f"  [dim]{preview[:200]}[/dim]")
        elif payload.get("hex_preview"):
            console.print(f"  [dim]HEX: {payload['hex_preview'][:64]}[/dim]")

    if info.get("decoded"):
        for d in info["decoded"]:
            console.print(f"  Decoded: {d['encoding']} ({d['confidence']:.0%} {d['status']})")


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


@app.command()
def decode(
    data: str = typer.Argument(..., help="Hex string, base64, or file path to decode"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
) -> None:
    """🔓 Decode a payload with all available decoders."""
    import base64 as b64

    from wiretap.decoders.registry import DecoderRegistry

    # Parse input
    raw: bytes
    data_path = Path(data)
    if data_path.exists():
        raw = data_path.read_bytes()
    else:
        try:
            raw = bytes.fromhex(data)
        except ValueError:
            try:
                raw = b64.b64decode(data)
            except Exception:
                raw = data.encode("utf-8")

    registry = DecoderRegistry()
    registry.discover()
    results = registry.decode_payload(raw)

    console.print(f"\n[cyan]Payload:[/] {len(raw)} bytes")

    table = Table(title="Decoder Results", box=box.SIMPLE_HEAVY)
    table.add_column("Decoder", style="cyan")
    table.add_column("Status")
    table.add_column("Confidence", justify="right")
    table.add_column("Preview")

    for r in results:
        status_color = "green" if r.status.name == "SUCCESS" else "yellow" if r.status.name == "PARTIAL" else "red"
        preview = ""
        if r.data is not None:
            preview = str(r.data)[:60]
        elif r.error:
            preview = r.error[:60]

        table.add_row(
            r.encoding,
            f"[{status_color}]{r.status.name}[/{status_color}]",
            f"{r.confidence:.0%}",
            preview,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


@app.command()
def compare(
    session_a: str = typer.Argument(..., help="First session ID"),
    session_b: str = typer.Argument(..., help="Second session ID"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """⚖️  Compare two capture sessions."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import ConnectionRepository, FrameRepository, SessionRepository
        from wiretap.analysis.comparator import SessionComparator

        sid_a, sid_b = UUID(session_a), UUID(session_b)

        async with session_factory() as db:
            sa = await SessionRepository.get(db, sid_a)
            sb = await SessionRepository.get(db, sid_b)
            if not sa or not sb:
                console.print("[red]One or both sessions not found[/]")
                return

            conns_a = await ConnectionRepository.list_by_session(db, sid_a)
            conns_b = await ConnectionRepository.list_by_session(db, sid_b)
            frames_a = await FrameRepository.list_by_session(db, sid_a)
            frames_b = await FrameRepository.list_by_session(db, sid_b)

        comparator = SessionComparator()
        result = comparator.compare(sid_a, conns_a, frames_a, sid_b, conns_b, frames_b)

        console.print(Panel(
            f"[bold cyan]⚖️  Session Comparison[/]\n\n"
            f"  A: {sa.name} ({result.frame_count_a} frames)\n"
            f"  B: {sb.name} ({result.frame_count_b} frames)",
            border_style="cyan",
        ))

        if result.endpoints_added:
            console.print(f"\n[green]+ New endpoints ({len(result.endpoints_added)}):[/]")
            for ep in result.endpoints_added[:10]:
                console.print(f"  + {ep[:80]}")

        if result.endpoints_removed:
            console.print(f"\n[red]- Removed endpoints ({len(result.endpoints_removed)}):[/]")
            for ep in result.endpoints_removed[:10]:
                console.print(f"  - {ep[:80]}")

        if result.pattern_differences:
            console.print(f"\n[yellow]⚠ Pattern differences:[/]")
            for diff in result.pattern_differences:
                console.print(f"  • {diff}")

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------


@app.command()
def plugins() -> None:
    """🔌 List installed plugins and decoders."""
    from wiretap.decoders.registry import DecoderRegistry
    from wiretap.plugins.registry import PluginRegistry

    # Decoders
    decoder_reg = DecoderRegistry()
    decoder_reg.discover()

    table = Table(title="Installed Decoders", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="cyan")
    table.add_column("Priority", justify="right")

    for d in decoder_reg.decoders:
        table.add_row(d.name, str(d.priority))

    console.print(table)

    # Plugins
    plugin_reg = PluginRegistry()
    plugin_reg.discover()

    ptable = Table(title="Installed Plugins", box=box.SIMPLE_HEAVY)
    ptable.add_column("Name", style="cyan")
    ptable.add_column("Version")
    ptable.add_column("Description")

    for info in plugin_reg.list_info():
        ptable.add_row(info.name, info.version, info.description)

    console.print(ptable)


# ---------------------------------------------------------------------------
# inspect (simplified — shows recent frames)
# ---------------------------------------------------------------------------


@app.command()
def inspect(
    session_id: str = typer.Argument(..., help="Session ID to inspect"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max frames to display"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """🔎 Inspect frames from a captured session."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import (
            ConnectionRepository, FrameRepository, PayloadRepository, SessionRepository,
        )
        from wiretap.utils.formatting import format_bytes, format_timestamp

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid, limit=limit)

            conn_map = {str(c.id): c for c in connections}

        table = Table(
            title=f"Frames: {session.name} (showing {len(frames)})",
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("Time", style="dim")
        table.add_column("Dir")
        table.add_column("Protocol", style="cyan")
        table.add_column("URL")
        table.add_column("Seq", justify="right")

        for i, f in enumerate(frames):
            conn = conn_map.get(str(f.connection_id))
            dir_style = "yellow" if f.direction.name == "SENT" else "blue"
            table.add_row(
                str(i),
                format_timestamp(f.timestamp),
                f"[{dir_style}]{f.direction.name}[/{dir_style}]",
                conn.protocol.name if conn else "",
                (conn.url if conn else "")[:60],
                str(f.sequence),
            )

        console.print(table)

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


@app.command("validate-price")
def validate_price(
    session_id: str = typer.Argument(..., help="Session ID to validate"),
    base_dir: Optional[Path] = typer.Option(None, "--base-dir"),
    log_level: str = typer.Option("WARNING", "--log-level"),
) -> None:
    """🧪 Validate price candidate fields against DOM visible price annotations."""

    async def _run() -> None:
        config = _get_config(base_dir, log_level=log_level)
        engine, session_factory = await _init_db(config)

        from wiretap.storage.repository import SessionRepository, ConnectionRepository, FrameRepository, PayloadRepository
        from wiretap.validators.price_validator import PriceValidator
        from wiretap.analysis.classification import BinaryClusteringEngine
        from wiretap.analysis.similarity import PriceCandidateDetector

        sid = UUID(session_id)

        async with session_factory() as db:
            session = await SessionRepository.get(db, sid)
            if not session:
                console.print(f"[red]Session {session_id} not found[/]")
                return

            connections = await ConnectionRepository.list_by_session(db, sid)
            frames = await FrameRepository.list_by_session(db, sid)
            
            payloads = {}
            for f in frames:
                if f.payload_id:
                    p = await PayloadRepository.get(db, f.payload_id)
                    if p:
                        payloads[f.payload_id] = p

        # 1. Cluster frames into families to identify binary ones
        binary_frames = [f for f in frames if f.is_binary and f.payload_id]
        binary_fps = []
        clustering_engine = BinaryClusteringEngine()

        for f in binary_frames:
            p = payloads.get(f.payload_id)
            if p:
                fp = clustering_engine.fingerprint_packet(
                    frame_id=f.id,
                    connection_id=f.connection_id,
                    direction=f.direction,
                    timestamp=f.timestamp,
                    payload_raw=p.raw_bytes,
                    sha256=p.sha256
                )
                binary_fps.append(fp)

        families = clustering_engine.cluster(binary_fps)

        # 2. Scan each family for price candidates
        detector = PriceCandidateDetector()
        all_candidates = []
        for fam in families:
            cands = detector.detect_prices(fam)
            for cand in cands:
                all_candidates.append((fam.id, cand))

        if not all_candidates:
            console.print("[yellow]No price tick candidates were detected by the scanner heuristic.[/]")
            from wiretap.storage.engine import close_database
            await close_database(engine)
            return

        # 3. Run validation against DOM annotations for all candidates
        validator = PriceValidator()
        reports = []
        
        async with session_factory() as db:
            for fam_id, cand in all_candidates:
                report = await validator.validate_candidate(
                    db=db,
                    session_id=sid,
                    family_id=fam_id,
                    offset=cand.offset,
                    size=cand.size,
                    endianness=cand.endianness,
                    value_type=cand.value_type,
                    scale_factor=cand.scale_factor,
                    json_path=cand.json_path,
                )
                reports.append((cand, report))

        # Sort reports by validation score descending
        reports.sort(key=lambda r: r[1].score, reverse=True)

        # Render styled scorecard table
        from rich.table import Table
        table = Table(title=f"Price Field Validation Scorecard - Session {session.name}", box=box.ROUNDED)
        table.add_column("Family", style="cyan")
        table.add_column("Field Detail", style="magenta")
        table.add_column("Type/Scale", style="green")
        table.add_column("Correlation (R)", style="yellow", justify="right")
        table.add_column("Avg Rel Error", style="red", justify="right")
        table.add_column("Score", style="bold", justify="right")
        table.add_column("Decision", style="bold", justify="center")

        for cand, rep in reports:
            decision = "[green]VALID PRICE[/]" if rep.is_valid else "[red]REJECTED[/]"
            if rep.json_path:
                field_detail = f"JSON Path: {rep.json_path}"
            else:
                field_detail = f"offset 0x{rep.offset:02x} ({rep.size}B {rep.endianness})"
            
            # Formatting scale factor safely
            scale_str = f"1/{int(rep.scale_factor)}" if rep.scale_factor != 1.0 else "1"
            type_scale = f"{rep.value_type} ({scale_str})" if rep.scale_factor != 1.0 else rep.value_type
            
            table.add_row(
                rep.family_id[:18],
                field_detail,
                type_scale,
                f"{rep.correlation:.6f}" if rep.match_count > 0 else "N/A",
                f"{rep.avg_relative_error * 100:.4f}%" if rep.match_count > 0 else "N/A",
                f"{rep.score}/100" if rep.match_count > 0 else "0/100 (No DOM data)",
                decision
            )

        console.print(table)
        console.print("")

        # Print the detailed breakdown for the best candidate
        best_cand, best_rep = reports[0]
        if best_rep.match_count > 0:
            best_detail = f"JSON Path: {best_rep.json_path}" if best_rep.json_path else f"Offset 0x{best_rep.offset:02x}"
            console.print(Panel(
                f"[bold cyan]🔍 Detailed Scorecard (Best Candidate: {best_detail})[/]\n\n"
                f"  • Correlation (R >= 0.999): [bold]{best_rep.score_breakdown.get('correlation_score', 0)}/40[/]\n"
                f"  • Relative Error (<= 0.05%): [bold]{best_rep.score_breakdown.get('error_score', 0)}/30[/]\n"
                f"  • Decimal/Scale Precision: [bold]{best_rep.score_breakdown.get('decimal_precision_score', 0)}/10[/]\n"
                f"  • Timeline Persistence: [bold]{best_rep.score_breakdown.get('persistence_score', 0)}/10[/]\n"
                f"  • Run/Session Stability: [bold]{best_rep.score_breakdown.get('session_stability_score', 0)}/10[/]\n\n"
                f"  [bold]Total Score: {best_rep.score}/100[/]\n"
                f"  Message: {best_rep.message}",
                border_style="cyan"
            ))

        from wiretap.storage.engine import close_database
        await close_database(engine)

    asyncio.run(_run())


@app.command()
def trace(
    protocol_name: str = typer.Argument(..., help="Protocol name (e.g. quotex)"),
    token: str = typer.Option(..., "--token", "-t", help="Authentication token"),
    asset: str = typer.Option("BTCUSD_otc", "--asset", "-a", help="Asset name to subscribe to"),
    is_demo: bool = typer.Option(True, "--demo/--live", help="Demo or Live account mode"),
) -> None:
    """📡 Connect and trace live protocol updates in real-time."""

    async def _run() -> None:
        from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
        from wiretap.core.adapter import EngineIOv3Adapter
        from wiretap.core.session import TokenSessionProvider
        from wiretap.core.client import ProtocolClient

        spec_dir = Path.cwd() / "specs" / protocol_name / "v1"
        if not spec_dir.exists():
            console.print(f"[red]Specification directory not found: {spec_dir}[/]")
            return

        impl = QuotexProtocolImplementation(str(spec_dir))
        adapter = EngineIOv3Adapter()
        session_provider = TokenSessionProvider(token)

        client = ProtocolClient(impl, adapter, session_provider)

        console.print(Panel(
            f"[bold green]📡 Starting Live Protocol Tracer[/]\n\n"
            f"  Protocol: [bold]{protocol_name}[/]\n"
            f"  Asset: {asset}\n"
            f"  Mode: {'Demo' if is_demo else 'Live'}\n"
            f"  State: Connecting...",
            border_style="green"
        ))

        try:
            async for packet in client.connect_and_stream(asset=asset, is_demo=is_demo):
                if hasattr(packet, "price"):
                    dir_arrow = "▲" if packet.direction == 1 else "▼"
                    dir_color = "green" if packet.direction == 1 else "red"
                    console.print(
                        f"[bold dim]{packet.asset}[/] @ {packet.timestamp}: "
                        f"[bold {dir_color}]{packet.price:.5f}[/] [{dir_color}]{dir_arrow}[/]"
                    )
                elif hasattr(packet, "direction") and not hasattr(packet, "price"):
                    console.print(f"[dim][Heartbeat] {packet.direction}[/]")
                elif hasattr(packet, "candles"):
                    console.print(f"[cyan][History] {packet.asset} ({len(packet.candles)} candles)[/]")
                else:
                    console.print(f"[yellow][Unknown] type={packet.packet_type} size={len(packet.raw_payload)}[/]")
        except KeyboardInterrupt:
            await client.disconnect()
            console.print("\n[yellow]Tracer stopped.[/]")

    asyncio.run(_run())


@app.command()
def simulate(
    session_id: str = typer.Argument(..., help="Session ID to simulate"),
    protocol_name: str = typer.Option("quotex", "--protocol", help="Protocol name (e.g. quotex)"),
    speed: float = typer.Option(1.0, "--speed", "-s", help="Playback speed multiplier"),
    db_path: str = typer.Option("wiretap.db", "--db", help="Database file path"),
) -> None:
    """▶️  Simulate protocol playback from database offline."""

    async def _run() -> None:
        from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
        from wiretap.replay.simulator import ReplaySimulator

        spec_dir = Path.cwd() / "specs" / protocol_name / "v1"
        if not spec_dir.exists():
            console.print(f"[red]Specification directory not found: {spec_dir}[/]")
            return

        impl = QuotexProtocolImplementation(str(spec_dir))
        sim = ReplaySimulator(db_path, session_id, impl, speed=speed)

        count = sim.load()
        if count == 0:
            console.print(f"[red]No protocol packets found in session {session_id}[/]")
            return

        console.print(Panel(
            f"[bold cyan]▶️  Protocol Replay Simulator[/]\n\n"
            f"  Session ID: {session_id}\n"
            f"  Total Packets: {count}\n"
            f"  Playback Speed: {speed}x",
            border_style="cyan"
        ))

        def callback(packet, frame):
            seq = frame["sequence"]
            if hasattr(packet, "price"):
                dir_color = "green" if packet.direction == 1 else "red"
                dir_arrow = "▲" if packet.direction == 1 else "▼"
                console.print(
                    f"[dim]#{seq}[/] [bold dim]{packet.asset}[/]: "
                    f"[bold {dir_color}]{packet.price:.5f}[/] [{dir_color}]{dir_arrow}[/]"
                )
            elif hasattr(packet, "direction") and not hasattr(packet, "price"):
                console.print(f"[dim]#{seq}[/] [dim][Heartbeat] {packet.direction}[/]")
            elif hasattr(packet, "candles"):
                console.print(f"[dim]#{seq}[/] [cyan][History] {packet.asset} ({len(packet.candles)} candles)[/]")
            else:
                console.print(f"[dim]#{seq}[/] [yellow][Unknown] type={packet.packet_type}[/]")

        await sim.run(callback)
        console.print("[green]Replay simulation finished.[/]")

    asyncio.run(_run())


@app.command()
def doctor(
    session_id: str = typer.Argument(..., help="Session ID to diagnose"),
    protocol_name: str = typer.Option("quotex", "--protocol", help="Protocol name (e.g. quotex)"),
    db_path: str = typer.Option("wiretap.db", "--db", help="Database file path"),
) -> None:
    """🩺 Analyze protocol drift and layout specification compliance."""

    async def _run() -> None:
        from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
        from wiretap.drift.drift_detector import DriftDetector
        import sqlite3

        spec_dir = Path.cwd() / "specs" / protocol_name / "v1"
        if not spec_dir.exists():
            console.print(f"[red]Specification directory not found: {spec_dir}[/]")
            return

        impl = QuotexProtocolImplementation(str(spec_dir))
        detector = DriftDetector(impl)

        # Load frames directly
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT frames.sequence, frames.is_binary, payloads.raw_bytes
            FROM frames
            JOIN payloads ON frames.payload_id = payloads.id
            JOIN connections ON frames.connection_id = connections.id
            WHERE connections.session_id = ?
            ORDER BY frames.sequence ASC;
        """, (session_id,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            console.print(f"[red]No packets found in session {session_id}[/]")
            return

        console.print(f"Diagnosing protocol drift for session [bold]{session_id}[/] ({len(rows)} packets)...")

        for seq, is_binary, raw_bytes in rows:
            try:
                if is_binary:
                    packet_type = raw_bytes[0]
                    payload = raw_bytes[1:]
                else:
                    text_str = raw_bytes.decode("utf-8", errors="ignore")
                    packet_type = int(text_str[0])
                    payload = text_str[1:]

                packet = impl.parse_payload(packet_type, payload)
                detector.inspect(packet)
            except Exception:
                pass

        report = detector.get_report()

        # Display Rich scorecard
        console.print("\n")
        console.print(Panel(
            f"[bold green]🩺 Protocol Doctor Compliance Diagnosis[/]\n\n"
            f"  • Total Packets Inspected: [bold]{report['total_processed']}[/]\n"
            f"  • Compliant Packets: [bold]{report['total_processed'] - report['validation_failures_count'] - report['unknown_packets_count']}[/]\n"
            f"  • Failed Layout Validation: [bold red]{report['validation_failures_count']}[/]\n"
            f"  • Unknown/Unregistered Packets: [bold yellow]{report['unknown_packets_count']}[/]\n\n"
            f"  [bold]Protocol Alignment Score: {report['drift_score_percentage']:.2f}%[/]",
            border_style="green" if report['drift_score_percentage'] >= 90.0 else "yellow" if report['drift_score_percentage'] >= 70.0 else "red"
        ))

        if report["validation_failures"]:
            console.print("\n[bold red]❌ Recent Layout Validation Failures:[/]")
            for f in report["validation_failures"]:
                console.print(f"  • [bold]{f['packet_type']}[/] failed checks: {', '.join(f['errors'])}")
                console.print(f"    Data: {f['packet_data']}")

        if report["unknown_packets_count"] > 0:
            console.print(f"\n[bold yellow]⚠ Unknown/Unregistered Packets ({report['unknown_packets_count']}):[/]")
            console.print("    These packets were logged. Standard protocol structures may have evolved.")

    asyncio.run(_run())


if __name__ == "__main__":
    app()

