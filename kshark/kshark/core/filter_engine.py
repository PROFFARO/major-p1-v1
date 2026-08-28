"""
Wireshark-accurate Display Filter Lexer, Parser & AST Evaluator for KShark.

Supports expressive grammar:
  comm == "bash" && syscall_id == 59
  threat != "BENIGN" && confidence >= 0.80
  event_type == "NET" && (dst_port == 443 || dst_port == 80)
  file_path contains "/etc/shadow"
  syscall in (105, 106, 125, 308)
"""

import re
from typing import Any, Dict, List, Optional, Tuple, Union


# ─────────────────────────────────────────────────────────────
# 1. Available Filter Fields & Types
# ─────────────────────────────────────────────────────────────

FILTER_FIELDS = {
    "no":               int,
    "time":             str,
    "timestamp_ns":     int,
    "pid":              int,
    "ppid":             int,
    "uid":              int,
    "gid":              int,
    "comm":             str,
    "exe_path":         str,
    "parent_comm":      str,
    "syscall":          str,
    "syscall_id":       int,
    "event_type":       str,
    "file_path":        str,
    "bytes_written":    int,
    "bytes_read":       int,
    "dst_ip":           str,
    "dst_port":         int,
    "threat":           str,
    "threat_name":      str,
    "confidence":       float,
    "mitre":            str,
    "mitre_id":         str,
    "info":             str,
}


# ─────────────────────────────────────────────────────────────
# 2. Tokenizer & Lexer
# ─────────────────────────────────────────────────────────────

class TokenType:
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    NUMBER = "NUMBER"
    OP_EQ = "=="
    OP_NEQ = "!="
    OP_GT = ">"
    OP_LT = "<"
    OP_GTE = ">="
    OP_LTE = "<="
    OP_CONTAINS = "contains"
    OP_MATCHES = "matches"
    OP_IN = "in"
    LOGIC_AND = "&&"
    LOGIC_OR = "||"
    LOGIC_NOT = "!"
    LPAREN = "("
    RPAREN = ")"
    COMMA = ","
    EOF = "EOF"


class Token:
    def __init__(self, type_: str, value: Any, pos: int):
        self.type = type_
        self.value = value
        self.pos = pos

    def __repr__(self):
        return f"Token({self.type}, {repr(self.value)})"


def tokenize(expr: str) -> List[Token]:
    """Tokenizes a display filter expression string."""
    tokens = []
    i = 0
    n = len(expr)

    while i < n:
        c = expr[i]

        if c.isspace():
            i += 1
            continue

        # Symbols & Operators
        if expr[i:i+2] == "==":
            tokens.append(Token(TokenType.OP_EQ, "==", i))
            i += 2
        elif expr[i:i+2] == "!=":
            tokens.append(Token(TokenType.OP_NEQ, "!=", i))
            i += 2
        elif expr[i:i+2] == ">=":
            tokens.append(Token(TokenType.OP_GTE, ">=", i))
            i += 2
        elif expr[i:i+2] == "<=":
            tokens.append(Token(TokenType.OP_LTE, "<=", i))
            i += 2
        elif expr[i:i+2] == "&&":
            tokens.append(Token(TokenType.LOGIC_AND, "&&", i))
            i += 2
        elif expr[i:i+2] == "||":
            tokens.append(Token(TokenType.LOGIC_OR, "||", i))
            i += 2
        elif c == ">":
            tokens.append(Token(TokenType.OP_GT, ">", i))
            i += 1
        elif c == "<":
            tokens.append(Token(TokenType.OP_LT, "<", i))
            i += 1
        elif c == "!":
            tokens.append(Token(TokenType.LOGIC_NOT, "!", i))
            i += 1
        elif c == "(":
            tokens.append(Token(TokenType.LPAREN, "(", i))
            i += 1
        elif c == ")":
            tokens.append(Token(TokenType.RPAREN, ")", i))
            i += 1
        elif c == ",":
            tokens.append(Token(TokenType.COMMA, ",", i))
            i += 1

        # Quoted Strings
        elif c in ('"', "'"):
            quote = c
            start = i
            i += 1
            str_val = []
            while i < n and expr[i] != quote:
                if expr[i] == "\\" and i + 1 < n:
                    i += 1
                    str_val.append(expr[i])
                else:
                    str_val.append(expr[i])
                i += 1
            if i >= n:
                raise ValueError(f"Unclosed string literal starting at position {start}")
            i += 1  # Skip closing quote
            tokens.append(Token(TokenType.STRING, "".join(str_val), start))

        # Numbers
        elif c.isdigit() or (c == "." and i + 1 < n and expr[i+1].isdigit()):
            start = i
            num_str = []
            is_float = False
            while i < n and (expr[i].isdigit() or expr[i] == "."):
                if expr[i] == ".":
                    is_float = True
                num_str.append(expr[i])
                i += 1
            val_str = "".join(num_str)
            val = float(val_str) if is_float else int(val_str)
            tokens.append(Token(TokenType.NUMBER, val, start))

        # Identifiers & Keywords
        elif c.isalnum() or c in ("_", "/", "-", "."):
            start = i
            ident = []
            while i < n and (expr[i].isalnum() or expr[i] in ("_", "/", "-", ".")):
                ident.append(expr[i])
                i += 1
            val = "".join(ident)
            low = val.lower()

            if low in ("and", "&&"):
                tokens.append(Token(TokenType.LOGIC_AND, "&&", start))
            elif low in ("or", "||"):
                tokens.append(Token(TokenType.LOGIC_OR, "||", start))
            elif low in ("not", "!"):
                tokens.append(Token(TokenType.LOGIC_NOT, "!", start))
            elif low == "contains":
                tokens.append(Token(TokenType.OP_CONTAINS, "contains", start))
            elif low == "matches":
                tokens.append(Token(TokenType.OP_MATCHES, "matches", start))
            elif low == "in":
                tokens.append(Token(TokenType.OP_IN, "in", start))
            else:
                tokens.append(Token(TokenType.IDENTIFIER, val, start))

        else:
            raise ValueError(f"Unexpected character '{c}' at position {i}")

    tokens.append(Token(TokenType.EOF, "", n))
    return tokens


# ─────────────────────────────────────────────────────────────
# 3. AST Nodes & Evaluator
# ─────────────────────────────────────────────────────────────

class ASTNode:
    def evaluate(self, event: Dict[str, Any]) -> bool:
        raise NotImplementedError


class BinaryOpNode(ASTNode):
    def __init__(self, left: ASTNode, op: str, right: ASTNode):
        self.left = left
        self.op = op
        self.right = right

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if self.op == "&&":
            return self.left.evaluate(event) and self.right.evaluate(event)
        elif self.op == "||":
            return self.left.evaluate(event) or self.right.evaluate(event)
        return False


class UnaryOpNode(ASTNode):
    def __init__(self, op: str, operand: ASTNode):
        self.op = op
        self.operand = operand

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if self.op in ("!", "not"):
            return not self.operand.evaluate(event)
        return False


class ComparisonNode(ASTNode):
    def __init__(self, field: str, op: str, value: Any):
        self.field = field.lower()
        self.op = op
        self.value = value

    def _get_field_val(self, event: Dict[str, Any]) -> Any:
        # Standardize aliases
        if self.field in ("threat", "threat_name"):
            return str(event.get("threat_name") or event.get("threat_type") or event.get("agreed_threat") or "BENIGN")
        if self.field in ("mitre", "mitre_id"):
            return str(event.get("mitre_id", ""))
        if self.field in ("syscall", "syscall_name"):
            return str(event.get("syscall", event.get("syscall_name", "")))
        if self.field in ("file_path", "filename", "path"):
            return str(event.get("file_path", event.get("filename", "")))
        return event.get(self.field, None)

    def evaluate(self, event: Dict[str, Any]) -> bool:
        val = self._get_field_val(event)
        if val is None:
            return False

        target = self.value

        if self.op == "in":
            if isinstance(target, (list, tuple, set)):
                return val in target or str(val) in [str(t) for t in target]
            return False


        # Type Coercion for scalar operators
        try:
            if isinstance(val, (int, float)) and isinstance(target, (int, float)):
                pass
            elif isinstance(val, (int, float)) and isinstance(target, str) and target.isdigit():
                target = int(target)
            else:
                val = str(val)
                target = str(target)
        except Exception:
            return False

        if self.op == "==":
            return val == target
        elif self.op == "!=":
            return val != target
        elif self.op == ">":
            return val > target
        elif self.op == "<":
            return val < target
        elif self.op == ">=":
            return val >= target
        elif self.op == "<=":
            return val <= target
        elif self.op == "contains":
            return str(target).lower() in str(val).lower()
        elif self.op == "matches":
            return bool(re.search(str(target), str(val), re.IGNORECASE))

        return False



# ─────────────────────────────────────────────────────────────
# 4. Recursive Descent Parser
# ─────────────────────────────────────────────────────────────

class DisplayFilterParser:
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def current(self) -> Token:
        return self.tokens[self.pos]

    def consume(self, expected_type: Optional[str] = None) -> Token:
        tok = self.current()
        if expected_type and tok.type != expected_type:
            raise ValueError(f"Expected token '{expected_type}' at pos {tok.pos}, got '{tok.type}'")
        self.pos += 1
        return tok

    def parse(self) -> ASTNode:
        node = self.expr_or()
        if self.current().type != TokenType.EOF:
            raise ValueError(f"Unexpected trailing input '{self.current().value}' at position {self.current().pos}")
        return node

    def expr_or(self) -> ASTNode:
        node = self.expr_and()
        while self.current().type == TokenType.LOGIC_OR:
            op_tok = self.consume()
            right = self.expr_and()
            node = BinaryOpNode(node, op_tok.value, right)
        return node

    def expr_and(self) -> ASTNode:
        node = self.expr_unary()
        while self.current().type == TokenType.LOGIC_AND:
            op_tok = self.consume()
            right = self.expr_unary()
            node = BinaryOpNode(node, op_tok.value, right)
        return node

    def expr_unary(self) -> ASTNode:
        if self.current().type == TokenType.LOGIC_NOT:
            op_tok = self.consume()
            operand = self.expr_unary()
            return UnaryOpNode(op_tok.value, operand)
        return self.expr_primary()

    def expr_primary(self) -> ASTNode:
        tok = self.current()

        if tok.type == TokenType.LPAREN:
            self.consume(TokenType.LPAREN)
            node = self.expr_or()
            self.consume(TokenType.RPAREN)
            return node

        if tok.type == TokenType.IDENTIFIER:
            field_name = self.consume().value
            op_tok = self.current()

            if op_tok.type in (TokenType.OP_EQ, TokenType.OP_NEQ, TokenType.OP_GT, TokenType.OP_LT,
                              TokenType.OP_GTE, TokenType.OP_LTE, TokenType.OP_CONTAINS, TokenType.OP_MATCHES):
                op = self.consume().value
                val_tok = self.current()
                if val_tok.type in (TokenType.STRING, TokenType.NUMBER, TokenType.IDENTIFIER):
                    val = self.consume().value
                    return ComparisonNode(field_name, op, val)
                else:
                    raise ValueError(f"Expected literal value at position {val_tok.pos}")

            elif op_tok.type == TokenType.OP_IN:
                self.consume(TokenType.OP_IN)
                self.consume(TokenType.LPAREN)
                items = []
                while self.current().type in (TokenType.STRING, TokenType.NUMBER, TokenType.IDENTIFIER):
                    items.append(self.consume().value)
                    if self.current().type == TokenType.COMMA:
                        self.consume(TokenType.COMMA)
                    else:
                        break
                self.consume(TokenType.RPAREN)
                return ComparisonNode(field_name, "in", items)

            else:
                # Single field presence check (e.g. `threat` -> `threat != BENIGN`)
                return ComparisonNode(field_name, "!=", "BENIGN" if field_name == "threat" else "")

        raise ValueError(f"Unexpected token '{tok.value}' at position {tok.pos}")


# ─────────────────────────────────────────────────────────────
# 5. Public API: Compile & Validate
# ─────────────────────────────────────────────────────────────

def compile_filter(filter_str: str) -> Optional[ASTNode]:
    """Compiles a filter string into an AST. Returns None if empty."""
    if not filter_str or not filter_str.strip():
        return None
    tokens = tokenize(filter_str)
    parser = DisplayFilterParser(tokens)
    return parser.parse()


def validate_filter(filter_str: str) -> Tuple[bool, str]:
    """
    Validates a filter string syntax.
    Returns (is_valid: bool, error_message: str).
    """
    if not filter_str or not filter_str.strip():
        return True, ""
    try:
        compile_filter(filter_str)
        return True, ""
    except Exception as e:
        return False, str(e)
