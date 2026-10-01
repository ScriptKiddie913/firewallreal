# Operations, Maintenance & Incident Response Runbooks

Operational procedures for managing, troubleshooting, and recovering SentinelFW in enterprise production environments.

## 1. Emergency Break-Glass & Failsafe Recovery

If autonomous threat response or administrator misconfiguration locks out management access:

```bash
# 1. Access node console via physical/IPMI/hypervisor terminal
# 2. Revert to safe-mode bypass policy
python3 sfwctl.py restore --safe-mode

# 3. Emergency unban all blocked IPs
python3 -c "from sentinelfw.engine import engine; engine.unban_all()"

# 4. Flush active nftables tables if dataplane is unresponsive
nft flush ruleset
```

## 2. Dynamic Secret Rotation & Vault Maintenance

```bash
# List sealed keys in vault
python3 -c "from sentinelfw.vault import vault; print(vault.list_keys())"

# Rotate VirusTotal or Sarvam AI API keys securely without restarting
python3 -c "from sentinelfw.vault import vault; vault.set('vt_api_key', 'NEW_KEY_HERE')"
```

## 3. High-Load Tuning & Kernel Parameters

For 10Gbps+ packet forwarding workloads:
- Increase conntrack table ceiling: `sysctl -w net.netfilter.nf_conntrack_max=2097152`
- Enable flowtable hardware offload in `config.json`: `"flowtable_offload": true`
- Bind packet capture threads to dedicated NUMA CPU cores.
