"""Tests for hash identification and cracking (no network)."""

import hashlib

from hashcrack import SaltMode, crack, identify

# md5("password"), sha1("password"), sha256("password")
MD5_PW = hashlib.md5(b"password").hexdigest()
SHA1_PW = hashlib.sha1(b"password").hexdigest()
SHA256_PW = hashlib.sha256(b"password").hexdigest()


def test_identify_md5_length():
    ident = identify(MD5_PW)
    assert "md5" in ident.candidates
    assert any("NTLM" in n for n in ident.notes)


def test_identify_sha1_and_sha256():
    assert "sha1" in identify(SHA1_PW).candidates
    assert "sha256" in identify(SHA256_PW).candidates


def test_identify_bcrypt_prefix():
    ident = identify("$2b$12$abcdefghijklmnopqrstuv")
    assert ident.candidates == ["bcrypt"]


def test_identify_non_hex():
    ident = identify("not-a-hash!!")
    assert ident.candidates == []


def test_identify_unknown_length():
    ident = identify("abcdef")  # 6 hex chars, no known algorithm
    assert ident.candidates == []


def test_crack_md5_builtin_wordlist():
    result = crack(MD5_PW, ["md5"])
    assert result.found
    assert result.password == "password"
    assert result.algorithm == "md5"


def test_crack_auto_algorithm_from_candidates():
    # sha256 length maps to [sha256, sha3_256]; cracking should still find it.
    result = crack(SHA256_PW, identify(SHA256_PW).candidates)
    assert result.found
    assert result.algorithm == "sha256"


def test_crack_case_insensitive_target():
    result = crack(MD5_PW.upper(), ["md5"])
    assert result.found and result.password == "password"


def test_crack_fails_when_word_not_in_list():
    target = hashlib.md5(b"an-unlikely-passphrase-xyz").hexdigest()
    assert not crack(target, ["md5"]).found


def test_crack_with_salt_prefix():
    salted = hashlib.sha256(b"s4lt" + b"admin").hexdigest()
    result = crack(salted, ["sha256"], salt="s4lt", salt_mode=SaltMode.PREFIX)
    assert result.found and result.password == "admin"


def test_crack_with_salt_suffix():
    salted = hashlib.sha1(b"letmein" + b"XYZ").hexdigest()
    result = crack(salted, ["sha1"], salt="XYZ", salt_mode=SaltMode.SUFFIX)
    assert result.found and result.password == "letmein"


def test_crack_with_custom_wordlist():
    target = hashlib.md5(b"hunter2").hexdigest()
    result = crack(target, ["md5"], wordlist=["nope", "hunter2"])
    assert result.found and result.password == "hunter2"
