"""SentinelFW Sarvam AI threat analyst.

Sends consolidated per-IP evidence (bans, threat vectors, traffic profile,
VirusTotal verdicts, IDS events) to the Sarvam-105B flagship model and gets
back a structured threat assessment used to identify novel threats the
static signature engine cannot classify.
"""
import json
import re
import time
import urllib.request
import urllib.error

from .common import event

SARVAM_CHAT_URL = "https://api.sarvam.ai/v1/chat/completions"

SYSTEM_PROMPT = (
    "You are SentinelFW's autonomous threat analyst, an expert SOC analyst for a "
    "Linux/Windows server firewall. You receive structured JSON evidence about a "
    "remote IP address. Assess whether the IP is a genuine threat, what kind of "
    "attack or service it represents, and whether the evidence suggests a novel "
    "or emerging threat pattern that static rules would miss. Be decisive and "
    "concise. Respond ONLY with a JSON object, no markdown, with these keys:\n"
    '{"verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",\n'
    ' "confidence": 0-100,\n'
    ' "threat_type": "short label e.g. port scanner, C2 beacon, CDN, cloud API",\n'
    ' "summary": "2-4 sentence plain-language assessment citing the evidence",\n'
    ' "reasoning": "brief step-by-step reasoning trace",\n'
    ' "recommended_actions": ["action1", "action2"],\n'
    ' "novel_threat": true|false}'
)


def _parse_reply(text: str, model: str, ip: str) -> dict:
    """Extracts the JSON object from the model reply (tolerates code fences)."""
    m = re.search(r"\{.*\}", text or "", re.S)
    data = {}
    if m:
        try:
            data = json.loads(m.group(0))
        except Exception:
            data = {}
    out = {
        "ip": ip,
        "ts": time.time(),
        "model": model,
        "verdict": str(data.get("verdict") or "UNKNOWN").upper()[:16],
        "confidence": max(0.0, min(100.0, float(data.get("confidence") or 0))),
        "threat_type": str(data.get("threat_type") or "")[:120],
        "summary": str(data.get("summary") or "")[:2000],
        "reasoning": str(data.get("reasoning") or "")[:4000],
        "recommended_actions": [str(a)[:200] for a in (data.get("recommended_actions") or [])][:8],
        "novel_threat": bool(data.get("novel_threat")),
    }
    return out


def analyze_ip(api_key: str, evidence: dict, model: str = "sarvam-105b",
               timeout: int = 60, base_url: str = "") -> dict:
    """Runs one threat assessment for the IP described in `evidence`.

    evidence: {"ip": ..., "ban": {...}|None, "offenses": int, "vectors": [...],
              "vt": {...}|None, "traffic": {...}, "events": [...]}
    base_url optionally overrides the Sarvam API endpoint (proxies / testing).
    Returns the assessment dict (also carries "error" on failure).
    """
    ip = str(evidence.get("ip") or "?")
    if not api_key:
        return {"ip": ip, "ts": time.time(), "model": model,
                "error": "no Sarvam API key configured (Settings → AI Threat Analyst)"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(evidence, default=str)[:100_000]},
        ],
        "temperature": 0.2,
        "top_p": 1,
        "max_tokens": 1500,
        "stream": False,
    }
    req = urllib.request.Request(
        (base_url or "").strip() or SARVAM_CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "api-subscription-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "SentinelFW/3",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
        text = (body.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return _parse_reply(text, model, ip)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        event("sarvam_api_error", "low", ip=ip, status=e.code, detail=detail)
        return {"ip": ip, "ts": time.time(), "model": model,
                "error": f"Sarvam API HTTP {e.code}: {detail or e.reason}"}
    except Exception as e:  # noqa: BLE001
        event("sarvam_api_error", "low", ip=ip, error=str(e)[:200])
        return {"ip": ip, "ts": time.time(), "model": model, "error": str(e)[:300]}
