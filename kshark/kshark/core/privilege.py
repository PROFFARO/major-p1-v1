"""
Linux Privilege Management & Polkit / pkexec Escalation Helper for KShark.

Handles root privilege detection and interactive authorization when attaching
eBPF kernel probes (kprobes, tracepoints, LSM hooks).
"""

import os
import shutil
import subprocess
import sys
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("kshark.privilege")



def is_root() -> bool:
    """Check if the current process has root privileges (UID 0)."""
    return os.geteuid() == 0


def can_elevate() -> bool:
    """Check if pkexec or sudo is available on the system."""
    return shutil.which("pkexec") is not None or shutil.which("sudo") is not None


def elevate_process(args: list = None) -> bool:
    """
    Relaunches the current command with elevated privileges using pkexec or sudo.
    Returns True if successfully spawned, False otherwise.
    """
    if is_root():
        return True

    cmd_args = args or sys.argv
    exec_path = sys.executable

    # Priority 1: pkexec (Standard Freedesktop GUI authorization modal)
    if shutil.which("pkexec"):
        try:
            logger.info("Requesting root privilege elevation via pkexec...")
            pkexec_cmd = ["pkexec", exec_path] + cmd_args
            subprocess.run(pkexec_cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.warning("pkexec elevation cancelled or failed: %s", e)
            return False
        except Exception as e:
            logger.error("Error executing pkexec: %s", e)

    # Priority 2: sudo in terminal environment
    if shutil.which("sudo"):
        try:
            logger.info("Requesting root privilege elevation via sudo...")
            sudo_cmd = ["sudo", exec_path] + cmd_args
            subprocess.run(sudo_cmd, check=True)
            return True
        except Exception as e:
            logger.error("Error executing sudo: %s", e)
            return False

    return False


def run_command_as_root(command: list) -> subprocess.CompletedProcess:
    """Run a specific sub-command (e.g. starting Go eBPF agent) as root."""
    if is_root():
        return subprocess.run(command, capture_output=True, text=True)

    if shutil.which("pkexec"):
        return subprocess.run(["pkexec"] + command, capture_output=True, text=True)

    if shutil.which("sudo"):
        return subprocess.run(["sudo"] + command, capture_output=True, text=True)

    raise PermissionError("Root privileges required but neither pkexec nor sudo is available.")


def spawn_agent_as_root(agent_path: str = None) -> Optional[subprocess.Popen]:
    """Spawns the Go eBPF agent in the background with elevated root privileges."""
    workspace_root = Path(__file__).resolve().parent.parent.parent.parent
    if agent_path is None:
        agent_path = str(workspace_root / "agent" / "ebpf-ml-agent")

    bpf_dir = str(workspace_root / "bpf" / "probes")

    if not os.path.exists(agent_path):
        logger.error("eBPF Agent binary not found at %s", agent_path)
        return None

    cmd = [agent_path, "--listen", ":8900", "--bpf-dir", bpf_dir]

    try:
        if is_root():
            return subprocess.Popen(cmd)
        if shutil.which("pkexec"):
            return subprocess.Popen(["pkexec"] + cmd)
        if shutil.which("sudo"):
            return subprocess.Popen(["sudo"] + cmd)
    except Exception as e:
        logger.error("Failed to spawn agent as root: %s", e)

    return None


