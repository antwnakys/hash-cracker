"""Dictionary-attack an unsalted hash by recomputing digests.

The whole point of this tool — and the security lesson behind it — is that fast,
general-purpose hashes (MD5, SHA-1, SHA-256) are a *terrible* way to store
passwords. Because they're fast and unsalted, an attacker who steals the hashes
can try millions of dictionary words per second **offline** and recover any
password that appears in a wordlist. That's what this does.

The takeaway: real password storage must use a *slow, salted* algorithm
(bcrypt, scrypt, Argon2) precisely to make this attack impractical.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

# A tiny built-in wordlist of the most common passwords, so the tool works out
# of the box for demos. A real attack uses a large list (e.g. rockyou.txt).
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "master", "sunshine", "admin", "welcome",
    "shadow", "ashley", "hunter2", "trustno1", "superman", "batman",
]


class SaltMode(str, Enum):
    NONE = "none"        # hash(word)
    PREFIX = "prefix"    # hash(salt + word)
    SUFFIX = "suffix"    # hash(word + salt)


@dataclass
class CrackResult:
    found: bool
    password: str | None = None
    algorithm: str | None = None
    attempts: int = 0


def _digest(word: str, algorithm: str, salt: str, mode: SaltMode) -> str:
    if mode is SaltMode.PREFIX:
        word = salt + word
    elif mode is SaltMode.SUFFIX:
        word = word + salt
    return hashlib.new(algorithm, word.encode("utf-8")).hexdigest()


def crack(
    target_hash: str,
    algorithms: Iterable[str],
    *,
    wordlist: Iterable[str] | None = None,
    salt: str = "",
    salt_mode: SaltMode = SaltMode.NONE,
) -> CrackResult:
    """Try each word under each algorithm; return the first match.

    Comparison is case-insensitive on the hex digest, so an upper- or lower-case
    target both work.
    """
    target = target_hash.strip().lower()
    algorithms = [a for a in algorithms if a in hashlib.algorithms_available]
    attempts = 0
    for word in (wordlist if wordlist is not None else COMMON_PASSWORDS):
        word = word.rstrip("\n")
        if not word:
            continue
        for algorithm in algorithms:
            attempts += 1
            if _digest(word, algorithm, salt, salt_mode) == target:
                return CrackResult(True, word, algorithm, attempts)
    return CrackResult(False, attempts=attempts)
