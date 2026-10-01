#!/usr/bin/env python3
"""Software Bill of Materials (SBOM) Generator for SentinelFW (Phase 35).

Generates a CycloneDX v1.5 JSON SBOM capturing all runtime, kernel, and management
subsystems with cryptographic SHA-256 hashes and license declarations.
"""
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def generate_sbom() -> dict:
    # Read version
    version = "4.0.0"
    common_file = ROOT / "sentinelfw" / "common.py"
    if common_file.exists():
        for line in common_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("VERSION ="):
                version = line.split("=")[1].strip().strip('"').strip("'")
                break

    components = [
        {
            "type": "application",
            "name": "sentinelfw-core",
            "version": version,
            "description": "SentinelFW Next-Generation Firewall & Autonomous Response Engine",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "purl": f"pkg:generic/sentinelfw@{version}",
        },
        {
            "type": "framework",
            "name": "sentinelgate-dataplane",
            "version": version,
            "description": "Go/nftables Stateful Dataplane & NAT Engine",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "purl": f"pkg:golang/github.com/sentinelfw/sentinelfw/pkg/dataplane@{version}",
        },
        {
            "type": "operating-system",
            "name": "ebpf-xdp-prefilter",
            "version": version,
            "description": "Ingress XDP packet pre-filter and line-rate scrubber",
            "licenses": [{"license": {"id": "GPL-2.0-only"}}],
            "purl": f"pkg:generic/ebpf-xdp-prefilter@{version}",
        },
        {
            "type": "library",
            "name": "python-stdlib",
            "version": "3.8+",
            "description": "Zero 3rd-party pip dependency runtime environment",
            "licenses": [{"license": {"id": "PSF-2.0"}}],
        },
    ]

    # Add core files with hashes
    key_files = [
        ROOT / "sentinelfw" / "engine.py",
        ROOT / "sentinelfw" / "stateful_engine.py",
        ROOT / "sentinelfw" / "policies.py",
        ROOT / "sentinelfw" / "identity.py",
        ROOT / "sentinelfw" / "ips.py",
        ROOT / "sentinelfw" / "malware.py",
        ROOT / "sentinelfw" / "dlp.py",
        ROOT / "sentinelfw" / "vdom.py",
        ROOT / "sentinelfw" / "vault.py",
        ROOT / "sentinelfw" / "webui.py",
        ROOT / "bpf" / "xdp_prefilter.c",
    ]

    for kf in key_files:
        if kf.exists():
            rel = kf.relative_to(ROOT).as_posix()
            components.append({
                "type": "file",
                "name": rel,
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": sha256_file(kf)}],
                "licenses": [{"license": {"id": "Apache-2.0" if not rel.startswith("bpf") else "GPL-2.0-only"}}],
            })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:sentinelfw-sbom-{int(time.time())}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "SentinelFW Project", "name": "generate_sbom.py", "version": version}],
            "component": {
                "type": "application",
                "name": "SentinelFW",
                "version": version,
                "description": "Enterprise Next-Generation Firewall and Unified Security Fabric",
            },
        },
        "components": components,
    }

    DIST.mkdir(exist_ok=True)
    out_file = DIST / "sbom-cyclonedx.json"
    out_file.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"[OK] CycloneDX SBOM generated: {out_file} ({len(components)} components)")
    return sbom


if __name__ == "__main__":
    generate_sbom()
