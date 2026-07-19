# 🔓 hash-cracker

Identify an unknown hash's algorithm, then **dictionary-crack** it by recomputing
digests against a wordlist. A hands-on demonstration of *why fast, unsalted
hashes are unsafe for passwords* — and a handy CTF tool.

```
$ python -m hashcrack identify 5f4dcc3b5aa765d61d8327deb882cf99
Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Length: 32 chars
Likely algorithm(s): md5
  note: 32 hex chars also matches NTLM (Windows password hash).

$ python -m hashcrack crack 5f4dcc3b5aa765d61d8327deb882cf99
Cracking against 24 word(s), algorithm(s): md5 ...
  CRACKED — password is 'password' (md5), after 2 attempts.
```

> Built as a learning project on **applied cryptography and password security**
> — the offensive counterpart to my breach/password checker — for a
> cybersecurity portfolio.

---

## The security lesson

MD5, SHA-1, and SHA-256 are **fast, general-purpose** hashes. That speed is
great for checksums — and terrible for passwords. If an attacker steals a
database of unsalted SHA-256 password hashes, they can hash millions of
dictionary words per second **offline** and recover any password that appears in
a wordlist. No server, no rate limiting, nothing to stop them.

This tool makes that concrete: give it a hash, and it recovers the password if
it's weak.

**The fix** is exactly what makes this attack impractical:

- **Salt** every hash (so identical passwords hash differently, defeating
  precomputed rainbow tables).
- Use a **slow, memory-hard** algorithm — **bcrypt, scrypt, or Argon2** —
  designed so each guess is expensive. That turns "millions per second" into a
  handful, making dictionary attacks infeasible.

(This tool deliberately handles only the *fast, unsalted* hashes — the unsafe
ones. bcrypt/Argon2 hashes are detected and reported as out of scope, which is
the point.)

---

## Usage

```bash
# Identify a hash's likely algorithm:
python -m hashcrack identify <hash>

# Dictionary-crack it (auto-detects the algorithm, built-in wordlist):
python -m hashcrack crack <hash>

# Use your own wordlist and/or force an algorithm:
python -m hashcrack crack <hash> -w rockyou.txt -a sha256

# Crack a salted hash (salt prepended or appended before hashing):
python -m hashcrack crack <hash> --salt s4lt --salt-mode prefix
```

Supported algorithms: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3.
`crack` exits non-zero when it recovers the password.

---

## How it works

- **`identify.py`** — maps a hash's length and character set to candidate
  algorithms (e.g. 32 hex chars → MD5, with a note that NTLM shares that length),
  and recognizes prefixed formats like bcrypt (`$2b$`) and Argon2.
- **`crack.py`** — for each word × candidate algorithm, recompute the digest
  (optionally with a salt prefix/suffix) and compare. Returns the first match.
- **`cli.py`** — the `identify` / `crack` commands.

## No external dependencies

Uses only the Python standard library (`hashlib`). `pytest` is needed only to
run the tests.

---

## Running the tests

```bash
pip install pytest
pytest
```

Fully offline: hashes are generated in-test with `hashlib`, then identified and
cracked — including salted (prefix/suffix) cases and strong passwords that must
**not** crack.

---

## Project layout

```
hash-cracker/
├── hashcrack/
│   ├── identify.py   # algorithm identification by length/charset
│   ├── crack.py      # dictionary attack (optional salt modes)
│   └── cli.py        # identify / crack commands
└── tests/            # pytest suite (no network)
```

## Ethics

Crack only hashes you own or are explicitly authorized to test (e.g. CTFs, your
own systems). Cracking other people's password hashes may be illegal. This is a
defensive/educational tool.

## License

[MIT](LICENSE) — free to use, learn from, and build on.
