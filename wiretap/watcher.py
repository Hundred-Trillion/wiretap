import asyncio
import os
import sys
import argparse
import urllib.request
import urllib.parse
from typing import Optional

from wiretap.protocols.quotex.implementation import QuotexProtocolImplementation
from wiretap.core.adapter import EngineIOv3Adapter
from wiretap.core.session import TokenSessionProvider
from wiretap.core.client import ProtocolClient
from wiretap.core.packets import PriceTick

async def notify_telegram(message: str, bot_token: str, chat_id: str):
    """Sends a notification to a Telegram bot."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    try:
        # Run synchronous urlopen in executor to prevent blocking the event loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: urllib.request.urlopen(req).read())
        print(f"Telegram notification sent successfully: '{message}'")
    except Exception as e:
        print(f"Failed to send Telegram notification: {e}", file=sys.stderr)

async def run_watcher(
    asset: str,
    target_price: float,
    operator: str,
    token: str,
    session_file: Optional[str],
    telegram_token: Optional[str],
    telegram_chat_id: Optional[str],
    one_shot: bool = False
):
    # Load spec from default package location or current directory
    spec_dir = os.path.join(os.getcwd(), "specs", "quotex", "v1")
    if not os.path.exists(spec_dir):
        # Fallback to local import path if run from project root
        spec_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "specs", "quotex", "v1")
    
    if not os.path.exists(spec_dir):
        print(f"Error: Specification directory not found at {spec_dir}", file=sys.stderr)
        return

    impl = QuotexProtocolImplementation(spec_dir)
    adapter = EngineIOv3Adapter()
    session_provider = TokenSessionProvider(token, session_file=session_file)
    
    client = ProtocolClient(impl, adapter, session_provider)
    
    print(f"Initializing QXBroker Watcher...")
    print(f"  Asset:        {asset}")
    print(f"  Condition:    Current Price {operator} {target_price}")
    print(f"  Mode:         {'One-Shot (Cron-style)' if one_shot else 'Streaming (Daemon-style)'}")
    
    triggered = False
    try:
        async for packet in client.connect_and_stream(asset=asset, is_demo=True):
            if isinstance(packet, PriceTick) and packet.asset == asset:
                price = packet.price
                print(f"[{packet.asset}] Live Price: {price:.5f}")
                
                # Check target condition
                is_condition_met = False
                if operator == ">=" and price >= target_price:
                    is_condition_met = True
                elif operator == "<=" and price <= target_price:
                    is_condition_met = True
                elif operator == ">" and price > target_price:
                    is_condition_met = True
                elif operator == "<" and price < target_price:
                    is_condition_met = True
                elif operator == "==" and abs(price - target_price) < 1e-9:
                    is_condition_met = True
                
                if is_condition_met:
                    msg = f"🎯 QXBroker Watcher: {asset} is now {price:.5f} (Condition: {operator} {target_price} met!)"
                    print(msg)
                    if telegram_token and telegram_chat_id:
                        await notify_telegram(msg, telegram_token, telegram_chat_id)
                    triggered = True
                    break
                
                if one_shot:
                    print(f"One-shot check complete. Condition not met. Exiting.")
                    break
    except KeyboardInterrupt:
        print("\nWatcher stopped by user.")
    except Exception as e:
        print(f"Error in watcher: {e}", file=sys.stderr)
    finally:
        await client.disconnect()
        
    if one_shot and not triggered:
        sys.exit(1) # Exit with non-zero code to indicate target wasn't met (useful for scripting)

def main():
    parser = argparse.ArgumentParser(description="QXBroker Wiretap Price Watcher Tool")
    parser.add_argument("--asset", default="BTCUSD_otc", help="Asset identifier (e.g. BTCUSD_otc)")
    parser.add_argument("--target", type=float, required=True, help="Target price trigger value")
    parser.add_argument("--operator", choices=[">", "<", ">=", "<=", "=="], default=">=", help="Comparison operator")
    parser.add_argument("--token", required=True, help="QXBroker/Quotex session token")
    parser.add_argument("--session-file", help="Path to session_details.json to load session cookies")
    parser.add_argument("--telegram-token", help="Telegram Bot API token")
    parser.add_argument("--telegram-chat-id", help="Telegram Chat ID to notify")
    parser.add_argument("--one-shot", action="store_true", help="Query current price once, evaluate, and exit")

    args = parser.parse_args()
    
    asyncio.run(run_watcher(
        asset=args.asset,
        target_price=args.target,
        operator=args.operator,
        token=args.token,
        session_file=args.session_file,
        telegram_token=args.telegram_token,
        telegram_chat_id=args.telegram_chat_id,
        one_shot=args.one_shot
    ))

if __name__ == "__main__":
    main()
