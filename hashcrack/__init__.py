"""hash-cracker — identify and dictionary-crack unsalted hashes.

Educational red-team / CTF tool that demonstrates why fast, unsalted hashes
(MD5, SHA-1, SHA-256) are unsafe for password storage.
"""

from .crack import COMMON_PASSWORDS, CrackResult, SaltMode, crack
from .identify import Identification, identify

__version__ = "1.0.0"

__all__ = [
    "identify",
    "Identification",
    "crack",
    "CrackResult",
    "SaltMode",
    "COMMON_PASSWORDS",
]
