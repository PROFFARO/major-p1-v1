"""
Linux x86_64 Syscall ID to Syscall Name Table.
Covers canonical Linux kernel system call numbers.
"""

LINUX_SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    102: "getuid",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    202: "futex",
    213: "epoll_create",
    217: "getdents64",
    218: "set_tid_address",
    228: "clock_gettime",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    273: "set_robust_list",
    274: "get_robust_list",
    280: "utimensat",
    281: "epoll_pwait",
    288: "accept4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    302: "prlimit64",
    318: "getrandom",
    322: "execveat",
    332: "statx",
    439: "faccessat2",
    441: "epoll_pwait2",
}


def resolve_syscall_name(event: dict) -> str:
    """Translates event dictionary to human-readable Linux syscall name."""
    # 1. Direct explicit string
    sc = event.get("syscall") or event.get("syscall_name")
    if sc and isinstance(sc, str) and not sc.isdigit():
        return sc

    # 2. Syscall ID lookup
    sc_id = event.get("syscall_id")
    if sc_id is not None:
        try:
            sc_id_int = int(sc_id)
            if sc_id_int in LINUX_SYSCALL_NAMES:
                return LINUX_SYSCALL_NAMES[sc_id_int]
            return f"sys_{sc_id_int}"
        except Exception:
            pass

    # 3. Event Type fallback
    ev_type = event.get("event_type_str") or event.get("event_type")
    if ev_type:
        return str(ev_type)

    return "sys_unknown"


def get_syscall_id(name: str) -> int:
    """Reverse lookup of syscall name to syscall ID."""
    if not name:
        return 0
    name_l = name.lower().strip()
    for sc_id, sc_name in LINUX_SYSCALL_NAMES.items():
        if sc_name == name_l:
            return sc_id
    return 0

