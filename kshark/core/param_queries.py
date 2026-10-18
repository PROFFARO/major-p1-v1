"""Parameterized SQL wrapper — replaces string-concatenated queries."""
from typing import List, Tuple, Any

def params(query_template: str, values: Tuple[Any, ...]) -> Tuple[str, Tuple[Any, ...]]:
    """Return (query_template, values); caller must use DB parameter binding."""
    return (query_template, values)
