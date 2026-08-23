"""
ADFA-LD Dataset Converter for eBPF-ML Security Engine.

Converts public ADFA-LD host syscall trace files into standardized JSONL
telemetry records compatible with `feature_extractor.py`.

Dataset categories mapped:
  - Training_Data_Master / Validation_Data_Master → BENIGN (0)
  - Adduser_*                                      → PRIVILEGE_ESCALATION (2)
  - Meterpreter_* / Java_Meterpreter_*             → REVERSE_SHELL (3)
  - Web_Shell_*                                    → DATA_EXFILTRATION (4)
  - Hydra_FTP_* / Hydra_SSH_*                      → REVERSE_SHELL / BRUTE_FORCE
"""

import json
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("ml_engine.adfa_converter")

ADFA_BASE_DIR = Path(__file__).resolve().parent / "adfa_ld" / "extracted" / "ADFA-LD"
OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "agent" / "data"

# ADFA-LD Syscall ID mapping to Linux x86_64 system call IDs (sample mapping)
# ADFA uses x86 (32-bit) syscall numbers. Standard 32-to-64 syscall translation table.
SYSCALL_MAPPING = {
    1: 60,    # exit -> sys_exit
    3: 0,     # read -> sys_read
    4: 1,     # write -> sys_write
    5: 2,     # open -> sys_open
    6: 3,     # close -> sys_close
    11: 59,   # execve -> sys_execve
    12: 12,   # chdir -> sys_chdir
    33: 21,   # access -> sys_access
    45: 12,   # brk -> sys_brk
    90: 9,    # mmap -> sys_mmap
    91: 11,   # munmap -> sys_munmap
    122: 105, # setuid -> sys_setuid
    125: 10,  # mprotect -> sys_mprotect
    192: 9,   # mmap2 -> sys_mmap
    197: 5,   # fstat64 -> sys_fstat
}


def convert_adfa_file(filepath: Path, pid: int, label_str: str) -> List[Dict]:
    """Reads space-separated syscall numbers from an ADFA file and creates telemetry events."""
    events = []
    try:
        with open(filepath, "r") as f:
            content = f.read().strip()
            if not content:
                return []
            tokens = content.split()
    except Exception as e:
        logger.debug("Failed reading %s: %s", filepath, e)
        return []

    base_ts = 10000000000000
    comm = "adfa_trace"
    parent_comm = "systemd"
    exe_path = "/usr/bin/adfa_binary"

    if "Adduser" in label_str:
        comm = "useradd"
        parent_comm = "bash"
        exe_path = "/usr/sbin/useradd"
    elif "Meterpreter" in label_str:
        comm = "meterpreter"
        parent_comm = "nc"
        exe_path = "/tmp/.payload"
    elif "Web_Shell" in label_str:
        comm = "php-cgi"
        parent_comm = "apache2"
        exe_path = "/var/www/html/shell.php"
    elif "Hydra" in label_str:
        comm = "hydra"
        parent_comm = "bash"
        exe_path = "/usr/bin/hydra"

    for i, tok in enumerate(tokens):
        try:
            raw_sc = int(tok)
        except ValueError:
            continue

        sc_id = SYSCALL_MAPPING.get(raw_sc, raw_sc)
        ts = base_ts + (i * 100000) # 100us increment per event

        event_type = 1 # SYSCALL
        filename = ""
        file_op = 0

        # Check file operations
        if sc_id in (2, 3, 21): # open, close, access
            event_type = 4 # FILE
            file_op = 1 # OPEN
        elif sc_id in (1,): # write
            event_type = 4 # FILE
            file_op = 3 # WRITE

        # Sensitive file hits for useradd/web_shell
        if "Adduser" in label_str and sc_id == 2:
            filename = "/etc/shadow"
        elif "Web_Shell" in label_str and sc_id == 2:
            filename = "/etc/passwd"

        ev = {
            "timestamp_ns": ts,
            "pid": pid,
            "tgid": pid,
            "ppid": 100,
            "uid": 1000 if "BENIGN" in label_str else 0,
            "gid": 1000,
            "cgroup_id": 100,
            "event_type": event_type,
            "event_type_str": "FILE" if event_type == 4 else "SYSCALL",
            "syscall_id": sc_id,
            "retval": 0,
            "comm": comm,
            "filename": filename,
            "file_op": file_op,
            "source": "adfa_importer",
            "exe_path": exe_path,
            "cmdline": exe_path,
            "parent_comm": parent_comm,
            "exe_hash": "adfa000000000000000000000000000000000000000000000000000000000000",
        }
        events.append(ev)

    return events


def run_conversion():
    """Converts all ADFA-LD trace directories into jsonl files."""
    if not ADFA_BASE_DIR.exists():
        logger.error("ADFA directory not found at %s", ADFA_BASE_DIR)
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Converting ADFA-LD traces to %s...", OUTPUT_DIR)

    all_events = []
    current_pid = 80000

    # 1. Process Attack Data
    attack_dir = ADFA_BASE_DIR / "Attack_Data_Master"
    if attack_dir.exists():
        for subfolder in sorted(attack_dir.iterdir()):
            if not subfolder.is_dir():
                continue
            folder_name = subfolder.name
            for trace_file in sorted(subfolder.glob("*.txt")):
                current_pid += 1
                evs = convert_adfa_file(trace_file, current_pid, folder_name)
                all_events.extend(evs)

    # 2. Process Training Data (Benign)
    train_dir = ADFA_BASE_DIR / "Training_Data_Master"
    if train_dir.exists():
        for trace_file in list(sorted(train_dir.glob("*.txt")))[:100]:
            current_pid += 1
            evs = convert_adfa_file(trace_file, current_pid, "BENIGN")
            all_events.extend(evs)

    out_file = OUTPUT_DIR / "adfa_converted_dataset.jsonl"
    logger.info("Writing %d converted ADFA events to %s...", len(all_events), out_file)

    with open(out_file, "w") as f:
        for ev in all_events:
            f.write(json.dumps(ev) + "\n")

    logger.info("ADFA-LD conversion complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    run_conversion()
