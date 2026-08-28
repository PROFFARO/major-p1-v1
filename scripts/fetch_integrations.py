#!/usr/bin/env python3
"""
Integration Script: Fetch 13 Industry-Leading eBPF GitHub Repositories.
Uses shallow clone (--depth 1) to ensure minimal memory and disk footprint.
"""

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTEGRATIONS_DIR = PROJECT_ROOT / "integrations"
INTEGRATIONS_DIR.mkdir(parents=True, exist_ok=True)

REPOSITORIES = [
    ("tetragon", "https://github.com/cilium/tetragon.git"),
    ("tracee", "https://github.com/aquasecurity/tracee.git"),
    ("sysmon", "https://github.com/microsoft/SysmonForLinux.git"),
    ("falco", "https://github.com/falcosecurity/falco.git"),
    ("ecapture", "https://github.com/gojue/ecapture.git"),
    ("netobserv", "https://github.com/netobserv/netobserv-ebpf-agent.git"),
    ("gadget", "https://github.com/inspektor-gadget/inspektor-gadget.git"),
    ("kubearmor", "https://github.com/kubearmor/KubeArmor.git"),
    ("pyroscope", "https://github.com/grafana/pyroscope.git"),
    ("parca", "https://github.com/parca-dev/parca.git"),
    ("kepler", "https://github.com/sustainable-computing-io/kepler.git"),
    ("eunomia", "https://github.com/eunomia-bpf/eunomia-bpf.git"),
    ("bpfman", "https://github.com/bpfman/bpfman.git"),
]

def main():
    print("=" * 70)
    print(" 🚀 Fetching 13 Open-Source eBPF Repositories into integrations/")
    print("=" * 70)
    
    for name, url in REPOSITORIES:
        target_path = INTEGRATIONS_DIR / name
        if target_path.exists():
            print(f" ✓ [{name}] already exists at {target_path}")
            continue
            
        print(f" 📦 Fetching [{name}] from {url}...")
        try:
            res = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target_path)],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"   ✓ [{name}] cloned successfully.")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed to clone [{name}]: {e.stderr.strip()}")
            
    print("=" * 70)
    print(" ✓ Acquisition complete! All 13 repositories present in integrations/")
    print("=" * 70)

if __name__ == "__main__":
    main()
