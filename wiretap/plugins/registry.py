"""Plugin registry — discovers and manages plugins.

Plugins are discovered via importlib.metadata entry points under
the 'wiretap.plugins' group. Additional plugins can be registered manually.
"""

from __future__ import annotations

from importlib.metadata import entry_points

import structlog

from wiretap.plugins.base import Plugin, PluginInfo

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """Registry of all available plugins."""

    def __init__(self) -> None:
        self._plugins: list[Plugin] = []
        self._log = structlog.get_logger(component="PluginRegistry")

    def discover(self) -> None:
        """Discover plugins from entry points."""
        eps = entry_points(group="wiretap.plugins")
        for ep in eps:
            try:
                plugin_cls = ep.load()
                plugin = plugin_cls()
                if isinstance(plugin, Plugin):
                    self.register(plugin)
                    self._log.info(
                        "plugin_loaded",
                        name=ep.name,
                        plugin=plugin.info.name,
                        version=plugin.info.version,
                    )
                else:
                    self._log.warning("plugin_invalid_protocol", name=ep.name)
            except Exception:
                self._log.error("plugin_load_failed", name=ep.name, exc_info=True)

    def register(self, plugin: Plugin) -> None:
        """Register a plugin manually."""
        self._plugins.append(plugin)

    def unregister(self, name: str) -> None:
        """Remove a plugin by name."""
        self._plugins = [p for p in self._plugins if p.info.name != name]

    @property
    def plugins(self) -> list[Plugin]:
        """All registered plugins."""
        return list(self._plugins)

    def list_info(self) -> list[PluginInfo]:
        """List metadata for all registered plugins."""
        return [p.info for p in self._plugins]
