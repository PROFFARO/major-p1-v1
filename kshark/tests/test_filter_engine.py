"""
Unit Tests for KShark Display Filter Lexer, Parser and AST Evaluator.
"""

from kshark.core.filter_engine import compile_filter, validate_filter


def test_simple_equality():
    ast = compile_filter('comm == "bash"')
    assert ast is not None
    assert ast.evaluate({"comm": "bash"})
    assert not ast.evaluate({"comm": "python3"})


def test_integer_comparison():
    ast = compile_filter("pid == 1234 && syscall_id >= 50")
    assert ast is not None
    assert ast.evaluate({"pid": 1234, "syscall_id": 59})
    assert not ast.evaluate({"pid": 1234, "syscall_id": 10})
    assert not ast.evaluate({"pid": 9999, "syscall_id": 59})


def test_logical_or_and_grouping():
    ast = compile_filter('(comm == "bash" || comm == "zsh") && (threat != "BENIGN" || confidence > 0.8)')
    assert ast is not None
    assert ast.evaluate({"comm": "bash", "threat_name": "RANSOMWARE", "confidence": 0.5})
    assert ast.evaluate({"comm": "zsh", "threat_name": "BENIGN", "confidence": 0.95})
    assert not ast.evaluate({"comm": "curl", "threat_name": "RANSOMWARE", "confidence": 0.95})


def test_contains_operator():
    ast = compile_filter('file_path contains "/etc/shadow"')
    assert ast is not None
    assert ast.evaluate({"file_path": "/etc/shadow.bak"})
    assert not ast.evaluate({"file_path": "/home/user/file.txt"})


def test_in_operator():
    ast = compile_filter("syscall_id in (59, 257, 105)")
    assert ast is not None
    assert ast.evaluate({"syscall_id": 59})
    assert ast.evaluate({"syscall_id": 257})
    assert not ast.evaluate({"syscall_id": 999})


def test_filter_validation():
    valid, err = validate_filter('comm == "bash" && pid == 1000')
    assert valid
    assert err == ""

    invalid, err = validate_filter('comm == && (pid')
    assert not invalid
    assert err != ""
