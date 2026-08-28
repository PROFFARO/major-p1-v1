#!/usr/bin/env python3
"""
Safe Linux OS Pseudo-Attack Generator.
Generates safe, non-destructive, but distinct behavioral and ML anomalies on Linux:
1. Spawns an ephemeral process from /tmp/ executing rapid mathematical calculations (Crypto Miner signature).
2. Performs world-writable temporary file operations.
3. Tests real-time ML anomaly detection and Falco behavioral rule triggers.
"""

import os
import sys
import time
import subprocess
import tempfile
import hashlib

def run_pseudo_miner(duration_seconds: int = 45):
    print("=" * 60)
    print("⚡ INITIATING SAFE OS PSEUDO-ATTACK: CRYPTO MINER WORKLOAD ⚡")
    print("=" * 60)

    # 1. Create a worker script in /tmp
    miner_script_path = "/tmp/xmrig_miner_worker.py"
    script_code = f"""#!/usr/bin/env python3
import time
import hashlib
import os

pid = os.getpid()
print(f"[Worker] Pseudo-miner started on PID: {{pid}} (comm: xmrig_miner_worker)")
end_time = time.time() + {duration_seconds}
count = 0
data = b"block_header_data_000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

last_log = time.time()
while time.time() < end_time:
    for i in range(1000):
        h = hashlib.sha256(data + str(count).encode()).hexdigest()
        count += 1
    
    # Periodic file write in /tmp
    if count % 5000 == 0:
        with open("/tmp/miner_hash_cache.tmp", "a") as f:
            f.write(f"Hash: {{h}}\\n")
            
    if time.time() - last_log >= 3.0:
        print(f"[Worker PID {{pid}}] Still active — computed {{count:,}} hashes...")
        last_log = time.time()
        
    time.sleep(0.005)

print(f"[Worker] Pseudo-miner completed ({{count:,}} total hashes computed).")
"""

    with open(miner_script_path, "w") as f:
        f.write(script_code)
    os.chmod(miner_script_path, 0o755)

    print(f"[*] Executable payload generated: {miner_script_path}")
    print("[*] Launching pseudo-miner subprocess...")

    proc = subprocess.Popen([sys.executable, miner_script_path])
    print(f"[*] Pseudo-miner running as PID: {proc.pid}")
    print("[*] Generating active OS telemetry for Stratoshark to capture...")
    print(f"[*] Active for next {duration_seconds} seconds...")

    return proc, miner_script_path

if __name__ == "__main__":
    proc, script_path = run_pseudo_miner(15)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        if os.path.exists(script_path):
            try:
                os.remove(script_path)
            except Exception:
                pass
        if os.path.exists("/tmp/miner_hash_cache.tmp"):
            try:
                os.remove("/tmp/miner_hash_cache.tmp")
            except Exception:
                pass
        print("[*] Cleaned up temporary test files.")
