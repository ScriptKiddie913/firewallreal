"""Quick standalone webui server on port 9444 for testing the updated code.

Set SENTINELFW_SIM=1 to also run the deterministic demo packet source
(synthetic packets injected into the NetLens recorder — dev/testing only).
"""
import os
import sys

# Use temp data dir to avoid locking conflicts with the running SYSTEM daemon
os.environ["SENTINELFW_HOME"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_test_data")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinelfw.engine import Engine
from sentinelfw.webui import SentinelWebUI
from sentinelfw.common import setup_logging, event, HOME

# Ensure test data directory exists
HOME.mkdir(parents=True, exist_ok=True)
setup_logging()

eng = Engine()
eng.lists.refresh()
event("test_webui_started", "info", port=9444)

webui = SentinelWebUI(
    host="127.0.0.1",
    port=9444,
    engine=eng,
    conntrack=eng.conntrack,
    honeypot=eng.honeypot,
    sandbox=eng.sandbox,
    baseline=eng.baseline,
)

# Start conntrack background thread so connections get populated
eng.conntrack.start()

# Optional synthetic packet stream for offline demo/testing
if os.environ.get("SENTINELFW_SIM") == "1":
    from sentinelfw.netlens import DemoPacketSource
    _demo = DemoPacketSource(eng.recorder, banned={"203.0.113.66"})
    _demo.ring = getattr(eng, "pcap_ring", None)
    _demo.start()
    print(">>> Demo packet simulator ACTIVE (synthetic traffic)")

# Spawn the default honeypot services so the deception page has data
if os.environ.get("SENTINELFW_NO_HONEYPOT") != "1":
    try:
        eng.honeypot.start_service("http", port=18080)
        eng.honeypot.start_service("ssh", port=12222)
    except Exception as e:
        print("honeypot spawn failed:", e)

print(">>> SentinelFW 3.0 TEST WebUI at http://127.0.0.1:9444")
print(">>> Press Ctrl+C to stop")
try:
    webui.serve_forever()
except KeyboardInterrupt:
    webui.shutdown()
    print("\nStopped.")
