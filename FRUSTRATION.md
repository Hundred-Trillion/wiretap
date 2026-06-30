# The Origin Story: Bypassing QXBroker APIs

This document records the background, motivations, and integration patterns for **Wiretap**, specifically detailing why it was started, how it was reverse-engineered, and how to connect it with autonomous agents like Nous Research's **Hermes Agent**.

---

## 😤 Why Wiretap Was Started
This project was born out of sheer frustration. If you have ever tried to automate, scrape, or build algorithmic trading watchers for platforms like **Quotex (QXBroker)**, you know that **there is no official API**. 

Frustrated by the lack of options, our creator spent **over 14 hours reverse-engineering WebSocket traffic** and another **4 hours of intensive "vibe-coding"**—testing raw binary frames, identifying offsets, parsing Engine.IO wrapper formats, and handling anti-bot connection protocols. 

The original goal was simple: **Build a reliable, lightweight watcher for QXBroker that alerts a Telegram bot when a certain price condition is met.** 

Instead of relying on heavy browser automation (which hogs RAM, leaks memory, and gets blocked by Cloudflare), we built **Wiretap** to fully reproduce the underlying protocol natively.

---

## ⚡ What Makes Wiretap Different?

Most automation tools rely on headless browsers (Playwright, Puppeteer, Selenium) to interact with the DOM or intercept traffic. Wiretap is completely different:

| Feature | Browser Automation (Playwright/Selenium) | Wiretap Native Protocol Client |
|---|---|---|
| **Memory Footprint** | 300MB - 1GB+ per tab | **< 35 MB RSS** |
| **CPU Overhead** | High (rendering engine, JS engine) | **Extremely Low** (pure network I/O) |
| **Cloudflare / Akamai** | Easily flagged via TLS/behavioral fingerprint | **Bypasses challenges** by sharing authenticated browser cookie state |
| **Long-Term Stability** | Prone to crashes, memory leaks, tab freezes | **Leak-free and stable** (tested continuously for long-duration streams) |
| **Declarative Customization** | Hardcoded selectors and DOM interactions | **JSON schemas (`specs/`)** map offsets, fields, and events |

---

## 🤖 Syncing with Nous Research's Hermes Agent

**Hermes Agent** is an autonomous, persistent AI agent designed to run continuously on servers or VPS instances. It is model-agnostic, maintains long-term memory, and uses tools to execute workflows.

Wiretap is designed to sync seamlessly with the Hermes Agent as an **MCP (Model Context Protocol) Server** or a **Custom Tool**.

### Why Integrate with Hermes?
*   **Persistent Monitoring**: Hermes runs 24/7 on a VPS, making it the perfect host to run a Wiretap price watcher.
*   **Autonomous Decision Making**: Hermes can observe the price stream, evaluate complex trading indicators, and decide when to alert your Telegram Bot.
*   **Natural Language Alerts**: Instead of simple raw numbers, Hermes can write structured market summaries and send them to you via Telegram/Discord.

### How to use Wiretap as a Hermes Tool
Define a tool/skill for your Hermes Agent using Wiretap's Python API:

```python
# hermes_skills/wiretap_watcher.py
import asyncio
from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
from wiretap.core.adapter import EngineIOv3Adapter
from wiretap.core.session import TokenSessionProvider
from wiretap.core.client import ProtocolClient
from wiretap.core.packets import PriceTick

# Define this function as a tool in your Hermes Agent config
async def watch_qxbroker_ticks(asset: str, target_price: float, token: str):
    """
    Monitors live QXBroker price ticks for a target asset.
    Triggers an action when the target price is crossed.
    """
    impl = QuotexProtocolImplementation("specs/quotex/v1")
    adapter = EngineIOv3Adapter()
    session_provider = TokenSessionProvider(token)
    
    client = ProtocolClient(impl, adapter, session_provider)
    
    print(f"Hermes Agent: Starting native watch on {asset} for target {target_price}")
    
    try:
        async for packet in client.connect_and_stream(asset=asset):
            if isinstance(packet, PriceTick):
                # Check target price condition
                if packet.price >= target_price:
                    alert_msg = f"🎯 Alert: {asset} hit target price of {packet.price}!"
                    print(alert_msg)
                    
                    # Trigger Hermes Agent action (e.g. notify Telegram Bot)
                    await notify_telegram(alert_msg)
                    break
    except Exception as e:
        print(f"Error in watcher tool: {e}")
    finally:
        await client.disconnect()

async def notify_telegram(message: str):
    # Standard Telegram bot notifier
    import urllib.request
    import urllib.parse
    bot_token = "YOUR_TELEGRAM_BOT_TOKEN"
    chat_id = "YOUR_CHAT_ID"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req) as response:
        return response.read()
```
