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


async def simulate_attack(mode="log_tampering", pid=99999, comm="malware_attack", dst_ip="192.168.1.222"):
    ws_url = "ws://localhost:8900/ws"
    print(f"[*] Connecting to eBPF Agent WebSocket at {ws_url}...")
    
    try:
        async with websockets.connect(ws_url) as ws:
            print(f"⚡ INJECTING THREAT TELEMETRY [{mode.upper()}] — PID: {pid} ({comm}) | Target IP: {dst_ip} ⚡")
            base_ns = int(time.time() * 1e9)
            
            for i in range(50):
                ts = base_ns + int(i * 0.05 * 1e9)
                
                if mode == "log_tampering":
                    evt = {
                        "event_type": 4, # FILE_OP
                        "timestamp_ns": ts,
                        "pid": pid,
                        "ppid": 1,
                        "uid": 0,
                        "gid": 0,
                        "comm": comm,
                        "exe_path": f"/tmp/{comm}",
                        "parent_comm": "bash",
                        "syscall_id": 2, # SYS_OPEN / WRITE
                        "file_path": "/etc/shadow" if i % 2 == 0 else "/var/log/auth.log",
                        "filename": "shadow" if i % 2 == 0 else "auth.log",
                        "file_op": 3,  # FILE_OP_WRITE
                        "bytes_written": 4096,
                        "bytes_read": 512,
                        "retval": 0,
                    }
                elif mode == "reverse_shell":
                    evt = {
                        "event_type": 5, # NET_OP
                        "timestamp_ns": ts,
                        "pid": pid,
                        "ppid": 1,
                        "uid": 1000,
                        "gid": 1000,
                        "comm": comm,
                        "exe_path": f"/usr/bin/{comm}",
                        "parent_comm": "bash",
                        "syscall_id": 41 if i % 3 == 0 else (42 if i % 3 == 1 else 44),
                        "dst_ip": dst_ip,
                        "dst_port": 4444,
                        "retval": 0,
                    }
                else: # Ransomware
                    evt = {
                        "event_type": 4,
                        "timestamp_ns": ts,
                        "pid": pid,
                        "ppid": 1,
                        "uid": 1000,
                        "gid": 1000,
                        "comm": comm,
                        "exe_path": f"/tmp/{comm}",
                        "parent_comm": "bash",
                        "syscall_id": 2,
                        "file_path": f"/tmp/user_data_{i}.encrypted",
                        "filename": f"user_data_{i}.encrypted",
                        "file_op": 3,
                        "bytes_written": 5242880,
                        "bytes_read": 1024,
                        "retval": 0,
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
    import argparse
    parser = argparse.ArgumentParser(description="eBPF Attack Simulation Tool")
    parser.add_argument("--mode", type=str, default="log_tampering", choices=["log_tampering", "reverse_shell", "ransomware"], help="Threat telemetry profile mode")
    parser.add_argument("--pid", type=int, default=None, help="Target PID (random if omitted)")
    args = parser.parse_known_args()[0]

    target_pid = args.pid or random.randint(70000, 89999)
    asyncio.run(simulate_attack(mode=args.mode, pid=target_pid, comm="malware_attack", dst_ip="192.168.1.222"))
