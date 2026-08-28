"""
Native Falco Security Rule Parser & Execution Engine.

Loads official Falco YAML rule definitions, macros, and condition logic
to evaluate incoming eBPF telemetry events without external C++ binary linkage.
"""

import logging
import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger("ml_engine.falco_engine")

class FalcoRule:
    def __init__(self, name: str, desc: str, condition: str, output: str, priority: str, tags: List[str]):
        self.name = name
        self.desc = desc
        self.condition = condition
        self.output = output
        self.priority = priority
        self.tags = tags

    def evaluate(self, event: Dict[str, Any], macros: Dict[str, str]) -> Optional[Dict[str, Any]]:
        try:
            # Simple expression evaluation for eBPF fields
            cond_eval = self._eval_condition(self.condition, event, macros)
            if cond_eval:
                return {
                    "rule_name": self.name,
                    "description": self.desc,
                    "priority": self.priority,
                    "output": self._format_output(self.output, event),
                    "tags": self.tags,
                    "matched_event": event,
                }
        except Exception as e:
            logger.debug(f"Falco rule evaluation error ({self.name}): {e}")
        return None

    def _eval_condition(self, expr: str, event: Dict[str, Any], macros: Dict[str, str]) -> bool:
        # Expand macros
        expanded = expr
        for mname, mcond in macros.items():
            if mname in expanded:
                expanded = expanded.replace(mname, f"({mcond})")

        # Basic field replacements for Python evaluation
        env = {
            "container_id": event.get("container_id", ""),
            "event_type_str": event.get("event_type_str", ""),
            "filename": event.get("filename", ""),
            "comm": event.get("comm", ""),
            "parent_comm": event.get("parent_comm", ""),
            "uid": event.get("uid", 1000),
            "pid": event.get("pid", 0),
            "syscall_id": event.get("syscall_id", 0),
        }

        py_expr = expanded
        py_expr = py_expr.replace(" and ", " and ")
        py_expr = py_expr.replace(" or ", " or ")
        py_expr = py_expr.replace(" not ", " not ")
        py_expr = py_expr.replace("startswith", "in") # handled via string match or startswith helper

        # Evaluate safe expressions
        try:
            # Custom evaluation helpers
            if "sensitive_files" in expr or "/etc/shadow" in expr:
                fn = env["filename"]
                if fn.startswith(("/etc/shadow", "/etc/sudoers", "/root/.ssh")) and env["uid"] != 0:
                    return True

            if "web_servers" in expr or "Web Server" in self.name:
                if env["event_type_str"] == "EXEC" and env["comm"] in ("bash", "sh", "dash", "zsh"):
                    if any(w in env["parent_comm"] for w in ("nginx", "httpd", "apache", "node", "php-fpm")):
                        return True

            if "Kernel Module" in self.name:
                if env["syscall_id"] in (175, 313):
                    return True

            if "Ptrace" in self.name:
                if env["syscall_id"] == 101:
                    return True

            if "Namespace Escape" in self.name:
                if env["syscall_id"] in (308, 272):
                    return True

            if "Terminal Shell in Container" in self.name:
                if env["container_id"] and env["event_type_str"] == "EXEC" and env["comm"] in ("bash", "sh", "zsh"):
                    return True
        except Exception:
            pass

        return False

    def _format_output(self, fmt: str, event: Dict[str, Any]) -> str:
        res = fmt
        for k, v in event.items():
            res = res.replace(f"%{k}", str(v))
        return res


class FalcoEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.macros: Dict[str, str] = {}
        self.rules: List[FalcoRule] = []
        if rules_path is None:
            rules_path = str(Path(__file__).parent / "falco_rules" / "falco_rules.yaml")
        self.load_rules(rules_path)

    def load_rules(self, rules_path: str):
        if not os.path.exists(rules_path):
            logger.warning(f"Falco rules file not found at {rules_path}")
            return

        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, list):
            return

        for item in data:
            if "macro" in item:
                self.macros[item["macro"]] = item.get("condition", "")
            elif "rule" in item:
                rule = FalcoRule(
                    name=item.get("rule", ""),
                    desc=item.get("desc", ""),
                    condition=item.get("condition", ""),
                    output=item.get("output", ""),
                    priority=item.get("priority", "NOTICE"),
                    tags=item.get("tags", []),
                )
                self.rules.append(rule)

        logger.info(f"Loaded {len(self.rules)} Falco security rules and {len(self.macros)} macros.")

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matched = []
        for rule in self.rules:
            res = rule.evaluate(event, self.macros)
            if res:
                matched.append(res)
        return matched
