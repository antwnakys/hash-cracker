"""Command-line interface for hash-cracker.

Usage::

    python -m hashcrack identify 5f4dcc3b5aa765d61d8327deb882cf99
    python -m hashcrack crack 5f4dcc3b5aa765d61d8327deb882cf99
    python -m hashcrack crack <sha256> -w rockyou.txt
    python -m hashcrack crack <hash> --salt s4lt --salt-mode prefix

`identify` narrows the algorithm; `crack` runs a dictionary attack. `crack`
exits non-zero when the hash is cracked, so it fits into scripts.

For authorized use only — crack hashes you own or are permitted to test.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .crack import COMMON_PASSWORDS, SaltMode, crack
from .identify import identify

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hashcrack",
        description="Identify and dictionary-crack unsalted hashes.",
    )
    parser.add_argument("--version", action="version", version=f"hash-cracker {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_id = sub.add_parser("identify", help="guess a hash's algorithm")
    p_id.add_argument("hash", help="the hash to identify")

    p_crack = sub.add_parser("crack", help="dictionary-attack a hash")
    p_crack.add_argument("hash", help="the hash to crack")
    p_crack.add_argument("-w", "--wordlist", help="wordlist file (default: built-in)")
    p_crack.add_argument("-a", "--algo", help="force a specific algorithm "
                         "(default: auto-detect from length)")
    p_crack.add_argument("--salt", default="", help="salt value, if any")
    p_crack.add_argument("--salt-mode", choices=[m.value for m in SaltMode],
                         default="none", help="how the salt is combined (default: none)")
    return parser.parse_args(argv)


def _load_wordlist(path: str | None):
    if not path:
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [line.rstrip("\n") for line in fh]


def _cmd_identify(args, use_color: bool) -> int:
    ident = identify(args.hash)
    bold = (lambda t: f"{_BOLD}{t}{_RESET}") if use_color else (lambda t: t)
    print(f"\n{bold('Hash')}: {ident.value}")
    print(f"Length: {len(ident.value)} chars")
    if ident.candidates:
        print("Likely algorithm(s): " + ", ".join(ident.candidates))
    else:
        print("Likely algorithm(s): unknown")
    for note in ident.notes:
        print(f"  note: {note}")
    print()
    return 0


def _cmd_crack(args, use_color: bool) -> int:
    paint = (lambda t, c: f"{c}{t}{_RESET}") if use_color else (lambda t, c: t)

    if args.algo:
        algorithms = [args.algo]
    else:
        ident = identify(args.hash)
        algorithms = ident.candidates
        if not algorithms:
            print("Could not identify the hash algorithm; specify one with --algo.",
                  file=sys.stderr)
            return 2

    wordlist = _load_wordlist(args.wordlist)
    n_words = len(wordlist) if wordlist is not None else len(COMMON_PASSWORDS)
    print(f"\nCracking against {n_words} word(s), algorithm(s): "
          f"{', '.join(algorithms)} ...")

    result = crack(
        args.hash, algorithms,
        wordlist=wordlist, salt=args.salt, salt_mode=SaltMode(args.salt_mode),
    )

    if result.found:
        print(paint(
            f"  CRACKED — password is {result.password!r} "
            f"({result.algorithm}), after {result.attempts} attempts.", _GREEN))
        print()
        return 1
    print(paint(f"  Not found ({result.attempts} attempts). "
                "Try a larger wordlist.", _YELLOW))
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    use_color = sys.stdout.isatty()
    if args.command == "identify":
        return _cmd_identify(args, use_color)
    return _cmd_crack(args, use_color)


if __name__ == "__main__":
    raise SystemExit(main())
