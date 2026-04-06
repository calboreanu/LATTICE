import json
from typing import Any, Dict

def canonicalize(obj: Dict[str, Any]) -> str:
    """Deterministic canonical form for hashing (stable key order, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
