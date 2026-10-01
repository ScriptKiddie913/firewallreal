# Software-Defined WAN (SD-WAN) & High Availability (HA)

SentinelFW provides carrier-grade WAN path selection, site-to-site mesh encryption, and Active-Passive / Active-Active cluster failover (`sentinelfw/sdwan.py`, `sentinelfw/vpn.py`, `sentinelfw/ha.py`).

## 1. SD-WAN Dynamic Path Selection

Traffic steering continuously optimizes across multiple uplinks (MPLS, Broadband, LTE/5G):
- **SLA Metrics:** Real-time round-trip latency, jitter, and packet loss measurement.
- **Application Policies:** Voice/Video pinned to lowest-jitter link; bulk data routed over broadband.
- **Route Flapping Hysteresis:** Prevents oscillating link flapping under marginal connection states by requiring sustained threshold satisfaction before path re-selection.

## 2. High Availability & VRRP State Machine

- **VRRP Failover:** Millisecond failover of virtual IPs across primary and secondary cluster firewalls.
- **Split-Brain Witness Fencing:** In the event of cluster link loss, a dedicated quorum witness node prevents dual-master split-brain conditions.
- **State Synchronization:** In-flight TCP connection tracking table and session states mirrored across peer nodes ensuring zero connection drops during planned or unplanned failover.
