"""SentinelFW Telegram Notification Engine.

Dispatches real-time security alerts and live logs to Telegram channels or chats
using BotFather bot tokens. Pure standard library implementation with asynchronous
worker thread, non-blocking event queue, and rate limiting.
"""
import json
import logging
import queue
import threading
import time
from typing import Dict, List, Optional
import urllib.parse
import urllib.request

from .common import STOP

logger = logging.getLogger("sentinelfw.telegram")


class TelegramNotifier:
    """Asynchronous background dispatcher for Telegram alerts."""

    def __init__(self, bot_token: str = "", chat_id: str = "",
                 alert_levels: Optional[List[str]] = None,
                 rate_limit_per_minute: int = 15, enabled: bool = False):
        self.bot_token = bot_token.strip()
        self.chat_id = str(chat_id).strip()
        self.alert_levels = set(l.lower() for l in (alert_levels or ["critical", "warning"]))
        self.rate_limit = max(1, rate_limit_per_minute)
        self.enabled = bool(enabled and self.bot_token and self.chat_id)
        
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._worker_thread: Optional[threading.Thread] = None
        self._window_start = time.time()
        self._sent_in_window = 0
        self._lock = threading.Lock()

    def update_config(self, bot_token: str, chat_id: str, enabled: bool,
                      alert_levels: Optional[List[str]] = None,
                      rate_limit_per_minute: int = 15):
        """Dynamically reconfigures the Telegram notifier."""
        with self._lock:
            self.bot_token = bot_token.strip()
            self.chat_id = str(chat_id).strip()
            if alert_levels is not None:
                self.alert_levels = set(l.lower() for l in alert_levels)
            self.rate_limit = max(1, rate_limit_per_minute)
            self.enabled = bool(enabled and self.bot_token and self.chat_id)
            if self.enabled and (not self._worker_thread or not self._worker_thread.is_alive()):
                self.start()

    def notify(self, event_data: dict):
        """Enqueue security event if alert level matches and notifier is enabled."""
        if not self.enabled:
            return
        
        severity = str(event_data.get("severity", "info")).lower()
        # If alert_levels includes all or specific level
        if severity in self.alert_levels or "all" in self.alert_levels:
            try:
                self._queue.put_nowait(event_data)
            except queue.Full:
                logger.warning("Telegram alert queue is full, dropping event")

    def notify_raw(self, message: str):
        """Enqueue raw log message."""
        if not self.enabled:
            return
        try:
            self._queue.put_nowait({"_raw_text": message, "severity": "info"})
        except queue.Full:
            pass

    def start(self):
        """Starts background worker thread."""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="telegram_notifier")
        self._worker_thread.start()

    def _worker_loop(self):
        while not STOP.is_set():
            now = time.time()
            if now - self._window_start >= 60.0:
                self._sent_in_window = 0
                self._window_start = now

            try:
                item = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            with self._lock:
                if not self.enabled or not self.bot_token or not self.chat_id:
                    continue

                if self._sent_in_window >= self.rate_limit:
                    time.sleep(1.0)
                    continue

            # Format and send
            if "_raw_text" in item:
                text = item["_raw_text"]
            else:
                text = self.format_event(item)

            success = self._send_api(self.bot_token, self.chat_id, text)
            if success:
                self._sent_in_window += 1
            else:
                time.sleep(2.0)

    def format_event(self, event: dict) -> str:
        """Formats security event into clean professional text without emojis."""
        sev = str(event.get("severity", "INFO")).upper()
        kind = event.get("kind", "SECURITY_ALERT")
        ts = event.get("ts", time.strftime("%Y-%m-%d %H:%M:%S"))

        lines = [
            f"[SENTINELFW {sev}] {kind.replace('_', ' ').upper()}",
            f"Timestamp : {ts}"
        ]

        if "src_ip" in event or "ip" in event:
            src = event.get("src_ip") or event.get("ip")
            port = event.get("src_port") or event.get("port", "")
            lines.append(f"Source IP : {src}{(':' + str(port)) if port else ''}")

        if "dst_ip" in event:
            lines.append(f"Target IP : {event.get('dst_ip')}:{event.get('dst_port', '')}")

        if "attack_type" in event:
            lines.append(f"Attack    : {event.get('attack_type')}")

        if "mitre_technique" in event:
            lines.append(f"MITRE     : {event.get('mitre_technique')}")

        if "action" in event:
            lines.append(f"Action    : {event.get('action')}")

        if "reason" in event:
            lines.append(f"Reason    : {event.get('reason')}")

        if "process" in event or "exe" in event:
            lines.append(f"Process   : {event.get('process') or event.get('exe')}")

        # Add remaining fields
        skip = {"sev", "severity", "kind", "ts", "src_ip", "ip", "src_port", "port",
                "dst_ip", "dst_port", "attack_type", "mitre_technique", "action", "reason",
                "process", "exe", "_raw_text"}
        extras = [f"{k}: {v}" for k, v in event.items() if k not in skip]
        if extras:
            lines.append("Details   : " + "; ".join(extras[:5]))

        return "\n".join(lines)

    @staticmethod
    def _send_api(bot_token: str, chat_id: str, text: str) -> bool:
        """Direct call to Telegram Bot API sendMessage."""
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Failed to send Telegram alert: %s", e)
            return False

    @staticmethod
    def send_test_message(bot_token: str, chat_id: str) -> Dict[str, any]:
        """Sends a verification message to confirm BotFather credentials."""
        token = bot_token.strip()
        cid = str(chat_id).strip()
        if not token or not cid:
            return {"ok": False, "error": "Bot token and Chat ID are both required"}

        test_msg = (
            "[SENTINELFW SYSTEM] TELEGRAM BOT CONNECTED\n"
            f"Timestamp : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            "Status    : Active\n"
            "Channel   : Security Log Dispatcher Online"
        )
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": cid,
            "text": test_msg,
            "disable_web_page_preview": True,
        }
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("ok"):
                    return {"ok": True, "message": "Test alert sent successfully to Telegram"}
                return {"ok": False, "error": data.get("description", "Unknown Telegram error")}
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
                err_data = json.loads(err_body)
                return {"ok": False, "error": err_data.get("description", str(e))}
            except Exception:
                return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


# Global instance
telegram_notifier = TelegramNotifier()
