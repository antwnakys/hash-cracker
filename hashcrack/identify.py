"""Identify the likely algorithm behind an unknown hash.

You can't know for *certain* which algorithm produced a bare hash — different
algorithms can share an output length (MD5 and NTLM are both 32 hex chars). But
the length and character set narrow it down to a small candidate set, which is
exactly what you need before trying to crack it.

This module maps a hash string to its candidate algorithms; :mod:`crack` then
tries each candidate against a wordlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# hex-digest length (in characters) -> candidate hashlib algorithm names.
# NTLM shares MD5's length but is a different algorithm; we note it as context.
_LENGTH_TO_ALGS: dict[int, list[str]] = {
    32: ["md5"],          # also NTLM (same length, different algorithm)
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384"],
    128: ["sha512", "sha3_512"],
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class Identification:
    value: str
    candidates: list[str]
    notes: list[str]


def identify(hash_str: str) -> Identification:
    """Return the candidate algorithms for ``hash_str`` (best-effort)."""
    value = hash_str.strip()
    notes: list[str] = []

    # A few unambiguous prefixed formats first.
    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return Identification(value, ["bcrypt"],
                              ["bcrypt is salted and slow — not crackable with "
                               "this simple wordlist tool."])
    if value.startswith("$argon2"):
        return Identification(value, ["argon2"],
                              ["Argon2 is memory-hard — out of scope for this tool."])
    if value.startswith("$6$"):
        return Identification(value, ["sha512crypt"],
                              ["Unix sha512crypt is salted — out of scope here."])

    if not _HEX_RE.match(value):
        return Identification(value, [],
                              ["Not a hex digest — may be base64, encrypted, or salted."])

    candidates = list(_LENGTH_TO_ALGS.get(len(value), []))
    if len(value) == 32:
        notes.append("32 hex chars also matches NTLM (Windows password hash).")
    if not candidates:
        notes.append(f"Unrecognized length ({len(value)} hex chars).")
    return Identification(value, candidates, notes)
