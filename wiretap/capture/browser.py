"""Browser lifecycle management via Playwright.

Handles launching Chromium, creating browser contexts (with optional
persistent profiles), and establishing CDP sessions for raw protocol access.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
from playwright.async_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Page,
    Playwright,
    async_playwright,
)

from wiretap.core.config import BrowserConfig

logger = structlog.get_logger(__name__)


class BrowserManager:
    """Manages Playwright browser lifecycle and CDP session creation.

    Usage:
        manager = BrowserManager(config)
        await manager.start()
        page = await manager.new_page()
        cdp = await manager.create_cdp_session(page)
        ...
        await manager.stop()

    Or as an async context manager:
        async with BrowserManager(config) as manager:
            page = await manager.new_page()
            ...
    """

    def __init__(self, config: BrowserConfig) -> None:
        self._config = config
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._log = structlog.get_logger(component="BrowserManager")

    async def start(self) -> None:
        """Launch the browser and create a context.

        If a profile_dir is configured, a persistent context is created
        to preserve login state and cookies across sessions.
        """
        self._playwright = await async_playwright().start()

        launch_args: list[str] = [
            "--disable-blink-features=AutomationControlled",
            *self._config.chromium_args,
        ]

        if self._config.profile_dir:
            # Persistent context preserves cookies, localStorage, etc.
            self._context = await self._playwright.chromium.launch_persistent_context(
                user_data_dir=str(self._config.profile_dir),
                headless=self._config.headless,
                slow_mo=self._config.slow_mo,
                args=launch_args,
                viewport={
                    "width": self._config.viewport_width,
                    "height": self._config.viewport_height,
                },
            )
            self._log.info(
                "browser_started",
                mode="persistent",
                profile=str(self._config.profile_dir),
                headless=self._config.headless,
            )
        else:
            self._browser = await self._playwright.chromium.launch(
                headless=self._config.headless,
                slow_mo=self._config.slow_mo,
                args=launch_args,
            )
            self._context = await self._browser.new_context(
                viewport={
                    "width": self._config.viewport_width,
                    "height": self._config.viewport_height,
                },
            )
            self._log.info(
                "browser_started",
                mode="ephemeral",
                headless=self._config.headless,
            )

    async def new_page(self) -> Page:
        """Create a new browser page in the current context.

        Returns:
            A new Playwright Page instance.

        Raises:
            RuntimeError: If the browser has not been started.
        """
        if self._context is None:
            raise RuntimeError("Browser not started. Call start() first.")
        page = await self._context.new_page()
        self._log.info("page_created")
        return page

    async def create_cdp_session(self, page: Page) -> CDPSession:
        """Create a Chrome DevTools Protocol session for a page.

        The CDP session enables raw protocol-level access to network
        events, bypassing Playwright's high-level abstractions.

        Args:
            page: The Playwright page to create a CDP session for.

        Returns:
            A CDPSession connected to the page.

        Raises:
            RuntimeError: If the browser context is not available.
        """
        if self._context is None:
            raise RuntimeError("Browser not started. Call start() first.")
        cdp = await self._context.new_cdp_session(page)
        self._log.info("cdp_session_created")
        return cdp

    async def stop(self) -> None:
        """Close the browser and release all resources."""
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        self._log.info("browser_stopped")

    @property
    def context(self) -> BrowserContext | None:
        """The current browser context, or None if not started."""
        return self._context

    async def __aenter__(self) -> BrowserManager:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()
