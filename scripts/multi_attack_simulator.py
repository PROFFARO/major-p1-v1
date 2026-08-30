#!/usr/bin/env python3
"""
Comprehensive Multi-Attack Simulation Suite for KShark eBPF & ML Engine.

Safely generates 4 distinct MITRE ATT&CK patterns on Linux OS:
1. RANSOMWARE: Rapid file encryption and batch renaming in a canary test folder.
2. REVERSE_SHELL: Outbound socket connection to C2 port from a spawned interactive worker.
3. CREDENTIAL_ACCESS: Probing sensitive credential paths and backup files.
4. PORT_SCAN / BRUTE_FORCE: High-frequency connect loops on local ports.
"""

import os
import sys
import time
import socket
import tempfile
import threading
import subprocess
from pathlib import Path

def run_ransomware_scenario(duration: int = 25):
    """Simulates ransomware encrypting canary files in a temporary sandbox."""
    sandbox_dir = Path("/tmp/kshark_canary_vault")
    sandbox_dir.mkdir(exist_ok=True)
    
    # Create 50 dummy documents
    for i in range(50):
        (sandbox_dir / f"confidential_doc_{i:03d}.docx").write_text(f"Important corporate record #{i}\n" * 20)

    worker_path = "/tmp/cryptolocker_worker.py"
    worker_code = f"""#!/usr/bin/env python3
import os, time, glob, hashlib

vault = "{sandbox_dir}"
end = time.time() + {duration}
print(f"[Ransomware Worker] PID: {{os.getpid()}} started — encrypting sandbox files...")

while time.time() < end:
    for fpath in glob.glob(f"{{vault}}/*"):
        if not fpath.endswith(".locked"):
            try:
                with open(fpath, "rb") as f:
                    content = f.read()
                # Overwrite with encrypted pseudo-ciphertext
                enc = hashlib.sha256(content).hexdigest().encode() * 4
                with open(fpath, "wb") as f:
                    f.write(enc)
                os.rename(fpath, fpath + ".locked")
            except Exception:
                pass
    time.sleep(0.1)

print("[Ransomware Worker] Encryption cycle completed.")
"""
    with open(worker_path, "w") as f:
        f.write(worker_code)
    os.chmod(worker_path, 0o755)

    print(f"\n[1/4] 🔒 Launching RANSOMWARE Simulation ({worker_path})...")
    p = subprocess.Popen([worker_path])
    print(f"      PID: {p.pid} | Process: cryptolocker_worker")
    return p, [sandbox_dir, Path(worker_path)]


def run_reverse_shell_scenario(duration: int = 25):
    """Simulates a reverse shell connecting back to a local C2 listener."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 4444))
    listener.listen(1)

    def listen_worker():
        try:
            listener.settimeout(duration + 5)
            conn, _ = listener.accept()
            while True:
                data = conn.recv(1024)
                if not data:
                    break
        except Exception:
            pass
        finally:
            listener.close()

    t = threading.Thread(target=listen_worker, daemon=True)
    t.start()

    worker_path = "/tmp/c2_reverse_shell.py"
    worker_code = f"""#!/usr/bin/env python3
import os, time, socket

end = time.time() + {duration}
print(f"[Reverse Shell Worker] PID: {{os.getpid()}} connected to C2 127.0.0.1:4444...")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 4444))
    while time.time() < end:
        s.sendall(b"whoami\\nid\\nuname -a\\ncat /etc/passwd\\n")
        time.sleep(0.5)
    s.close()
except Exception as e:
    print(f"[Reverse Shell] Error: {{e}}")

print("[Reverse Shell Worker] C2 Session finished.")
"""
    with open(worker_path, "w") as f:
        f.write(worker_code)
    os.chmod(worker_path, 0o755)

    print(f"\n[2/4] 🐚 Launching REVERSE SHELL Simulation ({worker_path})...")
    p = subprocess.Popen([worker_path])
    print(f"      PID: {p.pid} | Process: c2_reverse_shell -> 127.0.0.1:4444")
    return p, [Path(worker_path)]


def run_credential_dump_scenario(duration: int = 25):
    """Simulates credential harvesting / shadow file probe."""
    decoy_shadow = Path("/tmp/shadow.bak")
    decoy_shadow.write_text("root:$6$xyz$encrypted_root_hash:19000:0:99999:7:::\n")
    
    worker_path = "/tmp/shadow_dump_tool.py"
    worker_code = f"""#!/usr/bin/env python3
import os, time

end = time.time() + {duration}
print(f"[Credential Harvester] PID: {{os.getpid()}} probing credential stores...")

while time.time() < end:
    for target in ["/tmp/shadow.bak", "/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa"]:
        try:
            with open(target, "r") as f:
                _ = f.read(128)
        except Exception:
            pass
    time.sleep(0.2)

print("[Credential Harvester] Probing finished.")
"""
    with open(worker_path, "w") as f:
        f.write(worker_code)
    os.chmod(worker_path, 0o755)

    print(f"\n[3/4] 🔑 Launching CREDENTIAL DUMP Simulation ({worker_path})...")
    p = subprocess.Popen([worker_path])
    print(f"      PID: {p.pid} | Process: shadow_dump_tool")
    return p, [decoy_shadow, Path(worker_path)]


def run_port_scan_scenario(duration: int = 25):
    """Simulates high-speed TCP port / service discovery scan."""
    worker_path = "/tmp/port_scanner_probe.py"
    worker_code = f"""#!/usr/bin/env python3
import os, time, socket

end = time.time() + {duration}
print(f"[Port Scanner] PID: {{os.getpid()}} sweeping ports...")

ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200]
while time.time() < end:
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect(("127.0.0.1", p))
            s.close()
        except Exception:
            pass
    time.sleep(0.05)

print("[Port Scanner] Sweep finished.")
"""
    with open(worker_path, "w") as f:
        f.write(worker_code)
    os.chmod(worker_path, 0o755)

    print(f"\n[4/4] 📡 Launching PORT SCAN / RECONNAISSANCE Simulation ({worker_path})...")
    p = subprocess.Popen([worker_path])
    print(f"      PID: {p.pid} | Process: port_scanner_probe")
    return p, [Path(worker_path)]


def main():
    print("=" * 70)
    print("⚡ KSHARK MULTI-ATTACK SCENARIO GENERATOR ⚡")
    print("=" * 70)

    duration = 60
    procs = []
    cleanup_paths = []


    try:
        p1, paths1 = run_ransomware_scenario(duration)
        procs.append(p1)
        cleanup_paths.extend(paths1)

        p2, paths2 = run_reverse_shell_scenario(duration)
        procs.append(p2)
        cleanup_paths.extend(paths2)

        p3, paths3 = run_credential_dump_scenario(duration)
        procs.append(p3)
        cleanup_paths.extend(paths3)

        p4, paths4 = run_port_scan_scenario(duration)
        procs.append(p4)
        cleanup_paths.extend(paths4)

        print("\n" + "=" * 70)
        print(f"[*] All 4 unique attack workloads are ACTIVE simultaneously for {duration}s!")
        print("=" * 70)

        # Wait for all workers to finish
        for p in procs:
            p.wait()

    finally:
        print("\n[*] Cleaning up simulation artifacts...")
        for cp in cleanup_paths:
            try:
                if cp.is_dir():
                    import shutil
                    shutil.rmtree(cp, ignore_errors=True)
                elif cp.exists():
                    cp.unlink()
            except Exception:
                pass
        print("[✓] Cleaned up all temporary files.")

if __name__ == "__main__":
    main()
