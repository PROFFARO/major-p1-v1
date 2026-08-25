#!/usr/bin/env python3
"""
Attack Simulation Script for eBPF-ML Security System.

Simulates a high-intensity attack telemetry stream (Ransomware / Reverse Shell)
and injects it directly into the running Realtime Ingestion WebSocket endpoint (ws://localhost:8900/ws)
to trigger immediate ML threat detection and LSM kernel mitigation.
"""

import asyncio
import json
import random
import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import websockets
except ImportError:
    print("Installing websockets library...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
    import websockets


async def simulate_ransomware_attack(pid=99999, comm="nc_reverse_shell", dst_ip="192.168.1.100"):
    ws_url = "ws://localhost:8900/ws"
    print(f"[*] Connecting to eBPF Agent WebSocket at {ws_url}...")
    
    try:
        async with websockets.connect(ws_url) as ws:
            print(f"⚡ INJECTING HIGH-SEVERITY THREAT TELEMETRY — PID: {pid} ({comm}) | Target IP: {dst_ip} ⚡")
            base_ns = int(time.time() * 1e9)
            
            # Send 50 rapid anomalous syscall events matching REVERSE_SHELL / RANSOMWARE pattern
            for i in range(50):
                ts = base_ns + int(i * 0.05 * 1e9)
                event_type = 4 if i % 3 == 0 else (5 if i % 3 == 1 else 6)
                evt = {
                    "event_type": event_type,
                    "timestamp_ns": ts,
                    "pid": pid,
                    "ppid": 1,
                    "uid": 0,
                    "gid": 0,
                    "comm": comm,
                    "exe_path": f"/tmp/{comm}",
                    "parent_comm": "nc",
                    "syscall_id": 105 if i % 4 == 0 else (9 if i % 4 == 1 else (42 if i % 4 == 2 else 59)),
                    "file_path": "/etc/shadow" if i % 2 == 0 else "/etc/passwd",
                    "filename": "/etc/shadow" if i % 2 == 0 else "/etc/passwd",
                    "file_op": 3,  # FILE_OP_WRITE
                    "bytes_written": 1048576,
                    "bytes_read": 1024,
                    "dst_ip": dst_ip,
                    "dst_port": 4444,
                    "retval": -1 if i % 5 == 0 else 0,
                }
                await ws.send(json.dumps(evt))
                await asyncio.sleep(0.01)
                
            print("✔ Threat telemetry stream injection complete!")
            print("[*] Waiting 6 seconds for ingestion engine feature window aggregation & model evaluation...")
            await asyncio.sleep(6.0)
            
    except Exception as e:
        print(f"❌ Failed to connect to WebSocket: {e}")
        sys.exit(1)


if __name__ == "__main__":
    target_pid = random.randint(70000, 89999)
    asyncio.run(simulate_ransomware_attack(pid=target_pid, comm="malware_attack", dst_ip="192.168.1.222"))
