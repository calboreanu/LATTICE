"""
MANDATE Hashing and Canonicalization

Provides deterministic JSON canonicalization and SHA-256 hash computation
for MANDATE artifacts (anchor hashes, trace entry hashes, chain hashes).

Canonicalization
----------------
As of v1.3.0 this module uses **RFC 8785 (JSON Canonicalization Scheme)**
via the ``rfc8785`` library for all hash computation.  RFC 8785 guarantees
platform-independent, deterministic JSON encoding by specifying:

- ECMAScript-compatible number serialization (IEEE 754 doubles)
- UTF-16 lexicographic key sorting (recursive)
- Minimal encoding (no whitespace between tokens)
- Specific string escaping rules (control chars as ``\\uXXXX``)
- No Unicode normalization

For MANDATE's typical data (string/int keys, no ``-0.0``), the JCS output
is byte-identical to the v1.0–v1.2 pragmatic encoding.  See
``docs/hashing.md`` for the full migration story.

Legacy Support
--------------
``legacy_canonical_json()`` preserves the v1.0–v1.2 behaviour for
offline hash verification of pre-v1.3.0 artifacts.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, List

import rfc8785 as _jcs


# ── Canonicalization ─────────────────────────────────────────────────


def canonical_json(obj: Any) -> str:
    """
    RFC 8785 (JCS) deterministic JSON encoding used for hashing.

    Returns a UTF-8 string.  Internally delegates to ``rfc8785.dumps()``
    which returns bytes; we decode for convenience.

    .. versionchanged:: 1.3.0
       Switched from pragmatic ``json.dumps(sort_keys=True)`` to strict
       RFC 8785 via the ``rfc8785`` library.
    """
    return _jcs.dumps(obj).decode("utf-8")


def legacy_canonical_json(obj: Any) -> str:
    """
    Legacy (v1.0–v1.2) deterministic JSON encoding.

    Preserved for offline verification of artifacts produced before the
    RFC 8785 migration.  New code should always use :func:`canonical_json`.

    NOTE: This is a pragmatic canonicalization (sort_keys + stable
    separators).  It is NOT a full RFC 8785 implementation.
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


# ── SHA-256 Helpers ──────────────────────────────────────────────────


def sha256_hex(data: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_bytes_hex(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes (avoids redundant encode round-trip)."""
    return hashlib.sha256(data).hexdigest()


# ── Hash Computation ─────────────────────────────────────────────────


def compute_anchor_hash(anchor: Dict[str, Any]) -> str:
    """
    ``anchor_hash = sha256(jcs(anchor_without_anchor_hash))``
    """
    a = copy.deepcopy(anchor)
    a.pop("anchor_hash", None)
    return sha256_bytes_hex(_jcs.dumps(a))


def compute_trace_entry_hash(entry: Dict[str, Any]) -> str:
    """
    ``entry.hash = sha256(jcs(entry_without_hash))``
    """
    e = copy.deepcopy(entry)
    e.pop("hash", None)
    return sha256_bytes_hex(_jcs.dumps(e))


def compute_chain_hash(entries: List[Dict[str, Any]]) -> str:
    """
    Simple chain hash:
    ``sha256(jcs([entry.hash for entry in entries_in_order]))``
    """
    hashes = [e["hash"] for e in entries]
    return sha256_bytes_hex(_jcs.dumps(hashes))


def compute_chain_hash_from_strings(hashes: List[str]) -> str:
    """
    Compute chain hash from a list of hash strings directly.

    This is used when trace entries are stored as hash references
    rather than embedded objects.
    """
    return sha256_bytes_hex(_jcs.dumps(hashes))
