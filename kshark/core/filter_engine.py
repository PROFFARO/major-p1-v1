"""
KShark Display Filter Compiler & AST Evaluation Engine.
Comprehensive field alias mapping, Linux syscall name resolution, and bare-word search.
"""

import re
from typing import Dict, Any, Optional, List, Set

from kshark.core.syscall_table import resolve_syscall_name


FIELD_ALIASES = {
    # System call / Event type
    "evt.type": "syscall",
    "event.type": "syscall",
    "event": "syscall",
    "evt": "syscall",
    "type": "syscall",
    "syscall": "syscall",
    "syscall_name": "syscall",
    "syscall.name": "syscall",
    "sc": "syscall",

    # Process Name / Executable
    "proc.name": "comm",
    "process.name": "comm",
    "proc": "comm",
    "process": "comm",
    "comm": "comm",
    "cmd": "comm",
    "command": "comm",

    # Process ID / TID
    "proc.pid": "pid",
    "process.pid": "pid",
    "pid": "pid",
    "proc.ppid": "ppid",
    "process.ppid": "ppid",
    "ppid": "ppid",
    "thread.tid": "ppid",
    "tid": "ppid",

    # User / Permissions
    "user.uid": "uid",
    "user": "uid",
    "uid": "uid",
    "user.gid": "gid",
    "gid": "gid",
    "user.name": "uid",

    # File Descriptor / Target
    "fd.name": "file_path",
    "fd": "file_path",
    "file.path": "file_path",
    "file": "file_path",
    "filename": "file_path",
    "file_path": "file_path",
    "path": "file_path",
    "target": "file_path",
    "exe.path": "exe_path",
    "exe_path": "exe_path",
    "exe": "exe_path",

    # Network / Sockets
    "net.dst": "dst_ip",
    "ip.dst": "dst_ip",
    "dst.ip": "dst_ip",
    "dst_ip": "dst_ip",
    "ip": "dst_ip",
    "dst": "dst_ip",
    "net.port": "dst_port",
    "dst_port": "dst_port",
    "port": "dst_port",

    # Security & Threat Class
    "threat": "threat_name",
    "threat.name": "threat_name",
    "threat_name": "threat_name",
    "threat.class": "threat_name",
    "threat_class": "threat_name",
    "threat.type": "threat_name",
    "threat_type": "threat_name",
    "alert": "threat_name",
    "threat.confidence": "confidence",
    "confidence": "confidence",

    # Return Code & Errno
    "evt.res": "retval",
    "res": "retval",
    "ret": "retval",
    "retval": "retval",
    "errno": "retval",

    # Source Network Endpoints & Protocols
    "net.src": "src_ip",
    "ip.src": "src_ip",
    "src.ip": "src_ip",
    "src_ip": "src_ip",
    "net.srcport": "src_port",
    "src_port": "src_port",
    "net.proto": "net_proto",
    "proto": "net_proto",
    "protocol": "net_proto",

    # Execution & Working Directory
    "proc.cmdline": "cmdline",
    "cmdline": "cmdline",
    "args": "cmdline",
    "proc.cwd": "cwd",
    "cwd": "cwd",
    "proc.exe": "exe_path",

    # Container / CGroup
    "container.name": "container_name",
    "container": "container_name",
    "container_name": "container_name",
    "cgroup": "container_name",
    "cgroup_id": "container_name",
}


class ASTNode:
    def evaluate(self, event: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def matches(self, event: Dict[str, Any]) -> bool:
        return self.evaluate(event)



class FieldExistenceNode(ASTNode):
    """Evaluates bare field existence (e.g. 'threat', 'threat.name', 'net.dst')."""

    def __init__(self, field_alias: str):
        self.field = FIELD_ALIASES.get(field_alias.lower(), field_alias.lower())

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if self.field == "threat_name":
            th = event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or event.get("threat_class") or "BENIGN"
            return str(th).upper() not in ("BENIGN", "", "NONE")
        elif self.field == "dst_ip":
            dst = event.get("dst_ip") or event.get("net_dst") or ""
            return bool(dst and dst != "0.0.0.0")
        elif self.field == "file_path":
            fp = event.get("file_path") or event.get("filename") or event.get("exe_path") or ""
            return bool(fp and fp != "-")
        elif self.field == "syscall":
            sc = resolve_syscall_name(event)
            return bool(sc and sc != "sys_unknown")
        elif self.field == "comm":
            return bool(event.get("comm") or event.get("proc_name"))
        elif self.field == "retval":
            return int(event.get("retval", 0)) < 0

        val = event.get(self.field)
        return val is not None and str(val).strip() != ""


class LiteralComparisonNode(ASTNode):
    def __init__(self, field: str, op: str, value: Any):
        self.field = FIELD_ALIASES.get(field.lower(), field.lower())
        self.op = op.lower()
        self.value = value

    def evaluate(self, event: Dict[str, Any]) -> bool:
        val = event.get(self.field)

        # Field-specific resolvers
        if self.field == "syscall":
            val = resolve_syscall_name(event)
        elif self.field == "comm":
            val = event.get("comm") or event.get("proc_name") or ""
        elif self.field == "file_path":
            val = event.get("file_path") or event.get("filename") or event.get("exe_path") or ""
        elif self.field == "threat_name":
            val = event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or event.get("threat_class") or "BENIGN"
        elif self.field == "dst_ip":
            val = event.get("dst_ip") or event.get("net_dst") or ""
        elif self.field == "src_ip":
            val = event.get("src_ip") or "127.0.0.1"
        elif self.field == "retval":
            val = event.get("retval", 0)
        elif self.field == "net_proto":
            val = event.get("net_proto") or ("TCP" if int(event.get("dst_port", 0)) in (80, 443, 22, 4444, 1337) else "UDP")
        elif self.field == "cmdline":
            val = event.get("cmdline") or event.get("exe_path") or ""
        elif self.field == "container_name":
            val = str(event.get("container_name") or event.get("cgroup_id") or "host")

        if val is None:
            val = ""

        # String equality
        if self.op in ("==", "eq"):
            return str(val).lower() == str(self.value).lower()
        elif self.op in ("!=", "ne"):
            return str(val).lower() != str(self.value).lower()

        # String Substring & Regex
        elif self.op in ("contains", "~="):
            return str(self.value).lower() in str(val).lower()
        elif self.op in ("startswith", "^="):
            return str(val).lower().startswith(str(self.value).lower())
        elif self.op in ("endswith", "$="):
            return str(val).lower().endswith(str(self.value).lower())
        elif self.op in ("matches", "regex"):
            try:
                return bool(re.search(str(self.value), str(val), re.IGNORECASE))
            except Exception:
                return False

        # Numeric Comparisons
        elif self.op in (">", "gt"):
            try:
                return float(val) > float(self.value)
            except Exception:
                return False
        elif self.op in ("<", "lt"):
            try:
                return float(val) < float(self.value)
            except Exception:
                return False
        elif self.op in (">=", "ge"):
            try:
                return float(val) >= float(self.value)
            except Exception:
                return False
        elif self.op in ("<=", "le"):
            try:
                return float(val) <= float(self.value)
            except Exception:
                return False

        # Membership (in / not in)
        elif self.op == "in":
            if isinstance(self.value, (list, set, tuple)):
                return str(val).lower() in [str(x).lower() for x in self.value]
            return str(val).lower() in str(self.value).lower()
        elif self.op in ("not in", "not_in"):
            if isinstance(self.value, (list, set, tuple)):
                return str(val).lower() not in [str(x).lower() for x in self.value]
            return str(val).lower() not in str(self.value).lower()

        return False


class LogicalOpNode(ASTNode):
    def __init__(self, op: str, left: ASTNode, right: ASTNode):
        self.op = op.lower()
        self.left = left
        self.right = right

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if self.op in ("and", "&&"):
            return self.left.evaluate(event) and self.right.evaluate(event)
        elif self.op in ("or", "||"):
            return self.left.evaluate(event) or self.right.evaluate(event)
        return True


class NotOpNode(ASTNode):
    def __init__(self, child: ASTNode):
        self.child = child

    def evaluate(self, event: Dict[str, Any]) -> bool:
        return not self.child.evaluate(event)


class BareWordNode(ASTNode):
    def __init__(self, query: str):
        self.query = query.lower().strip('"\'')

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if not self.query:
            return True

        if self.query in ("threat", "threats"):
            th = event.get("threat_name") or event.get("threat_type") or "BENIGN"
            return str(th).upper() not in ("BENIGN", "", "NONE")

        # Check resolved syscall name
        sc_name = resolve_syscall_name(event).lower()
        if self.query == sc_name or self.query in sc_name:
            return True

        # Check process name
        comm = str(event.get("comm") or event.get("proc_name", "")).lower()
        if self.query in comm:
            return True

        # Check all values in event
        for k, v in event.items():
            if self.query in str(v).lower():
                return True
        return False


def _unwrap_parens(s: str) -> str:
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        matching = False
        for i, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if i == len(s) - 1:
                        matching = True
                    break
        if matching:
            s = s[1:-1].strip()
        else:
            break
    return s


def compile_filter(filter_str: str) -> Optional[ASTNode]:
    """Compiles a KShark / Wireshark filter string into an evaluatable ASTNode."""
    raw = filter_str.strip()
    if not raw:
        return None

    # Syntax Validation: Unbalanced parentheses
    if raw.count("(") != raw.count(")"):
        raise ValueError("Unbalanced parentheses in filter expression")

    # Syntax Validation: Unclosed quotes
    quote_double = len(re.findall(r'(?<!\\)"', raw))
    quote_single = len(re.findall(r"(?<!\\)'", raw))
    if quote_double % 2 != 0 or quote_single % 2 != 0:
        raise ValueError("Unclosed quote string in filter expression")

    # Syntax Validation: Invalid operator sequences (e.g. ==== or !==)
    if re.search(r'={3,}|!={2,}|>{3,}|<{3,}', raw):
        raise ValueError("Invalid comparison operator sequence")

    # Syntax Validation: Dangling trailing operators
    if re.search(r'(\b(and|or|not|in)\b|==|!=|>=|<=|>|<|&&|\|\||!)\s*$', raw, re.IGNORECASE):
        raise ValueError("Incomplete filter expression (trailing operator)")

    s = _unwrap_parens(raw)
    if not s:
        return None

    # Handle 'or' / '||' splits outside parentheses
    or_parts = _split_top_level(s, [r"\bor\b", r"\|\|"])

    if len(or_parts) > 1:
        nodes = [compile_filter(p) for p in or_parts]
        nodes = [n for n in nodes if n is not None]
        if not nodes:
            return None
        res = nodes[0]
        for n in nodes[1:]:
            res = LogicalOpNode("or", res, n)
        return res

    # Handle 'and' / '&&' splits outside parentheses
    and_parts = _split_top_level(s, [r"\band\b", r"\&\&"])
    if len(and_parts) > 1:
        nodes = [compile_filter(p) for p in and_parts]
        nodes = [n for n in nodes if n is not None]
        if not nodes:
            return None
        res = nodes[0]
        for n in nodes[1:]:
            res = LogicalOpNode("and", res, n)
        return res

    # Handle 'not' / '!' prefix
    if s.lower().startswith("not ") or s.startswith("!"):
        sub = s[4:] if s.lower().startswith("not ") else s[1:]
        child = compile_filter(sub.strip())
        if child:
            return NotOpNode(child)
        return None

    # Check for membership syntax: proc.name in ("curl", "bash", "python3")
    in_regex = r'([\w\.\_]+)\s+(in|not\s+in)\s+\(([^)]+)\)'
    m_in = re.match(in_regex, s, re.IGNORECASE)
    if m_in:
        field, op, raw_list = m_in.groups()
        items = [x.strip().strip('"\'') for x in raw_list.split(",") if x.strip()]
        return LiteralComparisonNode(field, op.lower(), items)

    # Standard Comparison parsing
    comp_regex = r'([\w\.\_]+)\s*(==|!=|>=|<=|>|<|contains|matches|startswith|endswith|~=|\^=|\$=)\s*("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\S+)'
    m = re.match(comp_regex, s, re.IGNORECASE)
    if m:
        field, op, val = m.groups()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        return LiteralComparisonNode(field, op, val)

    # Field existence check (e.g. 'threat', 'threat.name', 'net.dst', 'proc.name')
    if s.lower() in FIELD_ALIASES:
        return FieldExistenceNode(s.lower())

    # Bare word shorthand
    return BareWordNode(s)


def _split_top_level(s: str, patterns: List[str]) -> List[str]:
    """Splits string by regex pattern only at top parenthesis depth 0."""
    combined_pattern = "|".join(patterns)
    tokens = []
    depth = 0
    start = 0

    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            m = re.match(combined_pattern, s[i:], re.IGNORECASE)
            if m:
                tokens.append(s[start:i].strip())
                i += m.end()
                start = i
                continue
        i += 1

    tokens.append(s[start:].strip())
    return [t for t in tokens if t]
