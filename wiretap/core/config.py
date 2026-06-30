"""Wiretap configuration management.

Configuration is resolved in priority order:
1. Explicit constructor arguments
2. Environment variables (prefixed with WIRETAP_)
3. Default values
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_base_dir() -> Path:
    """Resolve the base directory for Wiretap data."""
    env = os.environ.get("WIRETAP_BASE_DIR")
    if env:
        return Path(env).resolve()
    return Path.cwd()


@dataclass(frozen=True)
class BrowserConfig:
    """Browser launch configuration."""

    headless: bool = False
    slow_mo: int = 0
    profile_dir: Path | None = None
    chromium_args: list[str] = field(default_factory=list)
    viewport_width: int = 1920
    viewport_height: int = 1080


@dataclass(frozen=True)
class CaptureConfig:
    """Capture session configuration."""

    max_payload_size: int = 10 * 1024 * 1024  # 10 MB
    store_response_bodies: bool = True
    capture_screenshots: bool = False
    annotation_window_ms: int = 2000


@dataclass(frozen=True)
class WiretapConfig:
    """Root configuration for the Wiretap framework."""

    base_dir: Path = field(default_factory=_default_base_dir)
    captures_dir: Path = field(default=Path(""))
    reports_dir: Path = field(default=Path(""))
    plugins_dir: Path = field(default=Path(""))
    database_path: Path = field(default=Path(""))
    log_level: str = "INFO"
    log_format: str = "console"
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)

    def __post_init__(self) -> None:
        """Resolve derived paths relative to base_dir."""
        if self.captures_dir == Path(""):
            object.__setattr__(self, "captures_dir", self.base_dir / "captures")
        if self.reports_dir == Path(""):
            object.__setattr__(self, "reports_dir", self.base_dir / "reports")
        if self.plugins_dir == Path(""):
            object.__setattr__(self, "plugins_dir", self.base_dir / "plugins")
        if self.database_path == Path(""):
            object.__setattr__(self, "database_path", self.base_dir / "wiretap.db")

        env_log_level = os.environ.get("WIRETAP_LOG_LEVEL")
        if env_log_level:
            object.__setattr__(self, "log_level", env_log_level.upper())

        env_log_format = os.environ.get("WIRETAP_LOG_FORMAT")
        if env_log_format:
            object.__setattr__(self, "log_format", env_log_format.lower())

    def ensure_directories(self) -> None:
        """Create all required directories if they do not exist."""
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls) -> WiretapConfig:
        """Create configuration from environment variables."""
        headless_env = os.environ.get("WIRETAP_HEADLESS", "").lower()
        headless = headless_env in ("1", "true", "yes")
        return cls(browser=BrowserConfig(headless=headless))
