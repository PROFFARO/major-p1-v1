"""
High-Volume eBPF Telemetry Dataset Generator.

Generates comprehensive, realistic, multi-scenario eBPF kernel telemetry JSONL files
containing over 200,000 events across benign system workloads and 6 MITRE ATT&CK categories.
"""

import json
import logging
import random
import time
from pathlib import Path

logger = logging.getLogger("generate_large_telemetry")

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "agent" / "data"

BENIGN_PROCESSES = [
    ("systemd", "/usr/lib/systemd/systemd", "systemd", 1),
    ("kwin_wayland", "/usr/bin/kwin_wayland", "systemd", 1100),
    ("antigravity", "/usr/share/antigravity/antigravity", "systemd", 24524),
    ("node", "/usr/bin/node", "bash", 30100),
    ("python3", "/usr/bin/python3", "bash", 30200),
    ("postgres", "/usr/lib/postgresql/postgres", "systemd", 1500),
    ("redis-server", "/usr/bin/redis-server", "systemd", 1600),
    ("nginx", "/usr/sbin/nginx", "systemd", 1700),
]

ATTACK_SCENARIOS = [
    ("RANSOMWARE", "lockbit_encryptor", "/tmp/lockbit.sh", "bash", 90001),
    ("PRIVILEGE_ESCALATION", "dirty_pipe_exploit", "/tmp/exploit", "bash", 90002),
    ("REVERSE_SHELL", "nc_backdoor", "/usr/bin/nc", "bash", 90003),
    ("DATA_EXFILTRATION", "dns_tunnel", "/tmp/dns_exfil.py", "python3", 90004),
    ("KERNEL_ROOTKIT", "rootkit_loader", "/tmp/rk.ko", "insmod", 90005),
    ("CRYPTO_MINER", "xmrig", "/tmp/.xmrig", "bash", 90006),
    ("BRUTE_FORCE", "ssh_hydra", "/usr/bin/hydra", "bash", 90007),
    ("CONTAINER_ESCAPE", "cgroup_escape", "/tmp/escape", "bash", 90008),
    ("LOG_TAMPERING", "log_wiper", "/tmp/clear_logs.sh", "bash", 90009),
    ("DENIAL_OF_SERVICE", "syn_flooder", "/tmp/flood", "bash", 90010),
]


def generate_dataset(num_events_per_file: int = 100000, num_files: int = 2):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    base_ts = int(time.time() * 1e9)

    for file_idx in range(num_files):
        out_file = OUTPUT_DIR / f"telemetry_large_gen_{file_idx+1}.jsonl"
        logger.info("Generating %d events into %s...", num_events_per_file, out_file)

        events = []
        cur_ts = base_ts + (file_idx * num_events_per_file * 50000)

        for i in range(num_events_per_file):
            cur_ts += random.randint(10000, 100000) # 10us - 100us step

            # 75% benign, 25% attack scenarios
            if random.random() < 0.75:
                comm, exe, parent, pid = random.choice(BENIGN_PROCESSES)
                pid_actual = pid + random.randint(0, 10)
                event_type = random.choice([1, 1, 1, 4, 5]) # mostly SYSCALL and FILE
                syscall_id = random.choice([0, 1, 2, 3, 7, 8, 9, 12, 16, 212, 217, 232, 257])
                retval = 0 if random.random() > 0.05 else -2 # ENOENT
                filename = "/usr/lib/libc.so" if event_type == 4 else ""
                file_op = random.choice([1, 2]) if event_type == 4 else 0
                source = "sys_tracer"
            else:
                attack_type, comm, exe, parent, pid_base = random.choice(ATTACK_SCENARIOS)
                pid_actual = pid_base
                source = "lsm_enforcer"

                if attack_type == "RANSOMWARE":
                    event_type = 4 # FILE
                    syscall_id = 257
                    retval = 0
                    filename = f"/home/user/document_{random.randint(1,500)}.docx.locked"
                    file_op = 3 # WRITE
                elif attack_type == "PRIVILEGE_ESCALATION":
                    event_type = 6 # PRIV
                    syscall_id = 105 # setuid
                    retval = 0
                    filename = "/etc/shadow"
                    file_op = 1
                elif attack_type == "REVERSE_SHELL":
                    event_type = 5 # NET
                    syscall_id = 42 # connect
                    retval = 0
                    filename = ""
                    file_op = 0
                elif attack_type == "DATA_EXFILTRATION":
                    event_type = 5 # NET
                    syscall_id = 44 # sendto
                    retval = 0
                    filename = "/etc/shadow"
                    file_op = 2
                elif attack_type == "KERNEL_ROOTKIT":
                    event_type = 7 # MEM
                    syscall_id = 10 # mprotect
                    retval = 0
                    filename = "/proc/kallsyms"
                    file_op = 1
                elif attack_type == "BRUTE_FORCE":
                    event_type = 1 # SYSCALL
                    syscall_id = 42 # connect
                    retval = -111 # ECONNREFUSED
                    filename = ""
                    file_op = 0
                elif attack_type == "CONTAINER_ESCAPE":
                    event_type = 6 # PRIV
                    syscall_id = 308 # setns
                    retval = 0
                    filename = "/sys/fs/cgroup/release_agent"
                    file_op = 3
                elif attack_type == "LOG_TAMPERING":
                    event_type = 4 # FILE
                    syscall_id = 87 # unlink
                    retval = 0
                    filename = f"/var/log/syslog.{random.randint(1,10)}"
                    file_op = 4 # UNLINK
                elif attack_type == "DENIAL_OF_SERVICE":
                    event_type = 5 # NET
                    syscall_id = 44 # sendto
                    retval = 0
                    filename = ""
                    file_op = 0
                else: # CRYPTO_MINER
                    event_type = 1 # SYSCALL
                    syscall_id = 1 # write
                    retval = 0
                    filename = ""
                    file_op = 0

            ev = {
                "timestamp_ns": cur_ts,
                "pid": pid_actual,
                "tgid": pid_actual,
                "ppid": 1000,
                "uid": 1000 if "attack_type" not in locals() else 0,
                "gid": 1000,
                "cgroup_id": 1234,
                "event_type": event_type,
                "event_type_str": "SYSCALL" if event_type == 1 else "FILE" if event_type == 4 else "NET" if event_type == 5 else "PRIV" if event_type == 6 else "MEM",
                "syscall_id": syscall_id,
                "retval": retval,
                "comm": comm,
                "filename": filename,
                "file_op": file_op,
                "source": source,
                "exe_path": exe,
                "cmdline": f"{exe} --run",
                "parent_comm": parent,
                "exe_hash": "a1b2c3d4e5f60789101112131415161718192021222324252627282930313233",
            }
            events.append(ev)

        with open(out_file, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        logger.info("Saved %d events to %s.", len(events), out_file)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    generate_dataset(num_events_per_file=100000, num_files=2)
