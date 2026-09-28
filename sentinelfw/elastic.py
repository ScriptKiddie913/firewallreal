"""SentinelFW Elasticsearch Shipper and Analytics Integration.

Ships security events, network flows, and attack detections to an Elasticsearch cluster
using pure Python stdlib urllib HTTP requests with automatic local spooling on network loss.
"""
import base64
import collections
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional
from .common import DATA_DIR, STOP, event

DEFAULT_TEMPLATE = {
    "index_patterns": ["sentinelfw-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "source_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "source_port": {"type": "integer"},
                "dest_port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "attack_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre_tactic": {"type": "keyword"},
                "mitre_technique": {"type": "keyword"},
                "kill_chain_phase": {"type": "keyword"},
                "total_score": {"type": "integer"},
                "confidence": {"type": "float"},
            }
        }
    }
}


class ElasticShipper(threading.Thread):
    """Batches, buffers, and ships events to Elasticsearch via NDJSON bulk API."""

    def __init__(self, cfg=None):
        super().__init__(name="elastic_shipper", daemon=True)
        self.cfg = cfg or {}
        es_cfg = self.cfg.get("elasticsearch", {})
        self.enabled = es_cfg.get("enabled", False)
        self.hosts = es_cfg.get("hosts", ["http://localhost:9200"])
        self.host = self.hosts[0] if self.hosts else "http://localhost:9200"
        self.username = es_cfg.get("username", "")
        self.password = es_cfg.get("password", "")
        self.prefix = es_cfg.get("index_prefix", "sentinelfw")
        self.bulk_size = int(es_cfg.get("bulk_size", 500))
        self.flush_interval = float(es_cfg.get("flush_interval_seconds", 5))

        self.spool_dir = DATA_DIR / "elastic_spool"
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._queue = collections.deque(maxlen=10000)
        self._lock = threading.RLock()
        self._last_flush = time.time()
        self.is_connected = False

    def ship_event(self, doc: dict, index_suffix: str = "events"):
        """Queues an event record for Elasticsearch indexing."""
        if not self.enabled:
            return
        with self._lock:
            self._queue.append((index_suffix, doc))

    def run(self):
        """Background flush loop."""
        while not STOP.is_set():
            time.sleep(1.0)
            if not self.enabled:
                continue

            now = time.time()
            with self._lock:
                should_flush = len(self._queue) >= self.bulk_size or (now - self._last_flush >= self.flush_interval and self._queue)

            if should_flush:
                self.flush()

    def flush(self) -> int:
        """Sends pending queued events via Elasticsearch _bulk endpoint."""
        batch = []
        with self._lock:
            while self._queue and len(batch) < self.bulk_size:
                batch.append(self._queue.popleft())
            self._last_flush = time.time()

        if not batch:
            return 0

        # Construct NDJSON payload
        today = time.strftime("%Y.%m.%d")
        lines = []
        for suffix, doc in batch:
            idx_name = f"{self.prefix}-{suffix}-{today}"
            action = {"index": {"_index": idx_name}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc))

        ndjson_body = "\n".join(lines) + "\n"
        url = f"{self.host.rstrip('/')}/_bulk"

        req = urllib.request.Request(
            url,
            data=ndjson_body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST"
        )

        if self.username and self.password:
            auth_str = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {auth_str}")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    self.is_connected = True
                    return len(batch)
        except Exception as e:
            self.is_connected = False
            # Spool to local disk for later replay
            self._spool_to_disk(batch)
            event("elastic_ship_error", "low", error=str(e), queued=len(batch))

        return 0

    def _spool_to_disk(self, batch: List):
        spool_file = self.spool_dir / f"spool_{int(time.time() * 1000)}.jsonl"
        try:
            with open(spool_file, "a", encoding="utf-8") as f:
                for suffix, doc in batch:
                    f.write(json.dumps({"suffix": suffix, "doc": doc}) + "\n")
        except OSError:
            pass

    def setup_template(self) -> bool:
        """Installs the index template on the Elasticsearch cluster."""
        url = f"{self.host.rstrip('/')}/_index_template/sentinelfw_template"
        req = urllib.request.Request(
            url,
            data=json.dumps(DEFAULT_TEMPLATE).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT"
        )
        if self.username and self.password:
            auth_str = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {auth_str}")

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201)
        except Exception:
            return False
