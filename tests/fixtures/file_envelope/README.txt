LEVFILE GOLDEN FIXTURE — DO NOT DELETE OR REGENERATE
=====================================================

golden.levault is a byte-frozen artefact of the v1 file-envelope format
(crypto.build_file_envelope / open_file_envelope, FILE_MAGIC = b"LEVFILE\0",
FILE_FORMAT_VERSION = 1).

It was generated once with:

  fmk       : bytes(range(32))
              = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  fmk_id    : "FIXTURE1"
  plaintext : b"-----BEGIN FIXTURE KEY-----\n"
              b"this is not a real key, it is a format tripwire\n"
              b"-----END FIXTURE KEY-----\n"
  meta      : {"name": "fixture.pem", "mode": "0600", "mtime": 1700000000.0,
               "sha256": "602c8f3b05224ad47fb62a500a1d36976c9ba9b9eb22acd6cb69e53db6d9780a"}

That key is deliberately public and worthless — it protects a fixed test
string, nothing else. Do not read anything into it being in the repo.

WHY THIS FILE EXISTS
--------------------
Every other test in test_file_vault_crypto.py round-trips through the CURRENT
code: it encrypts with build_file_envelope and decrypts with
open_file_envelope. That proves the two agree with each other. It does not
prove either still agrees with the format that is already on real users' disks
and, by design, committed to their git repositories.

A refactor that changed the header layout, the AAD construction, the HKDF info
string, or the inner meta framing would keep every round-trip test green while
silently making every .levault file in the world unopenable — and unlike the
vault, the plaintext for those files was deliberately destroyed.

This fixture is the tripwire for that. test_golden_fixture_still_opens reads
these exact bytes and asserts the exact expected plaintext and metadata.

IF THAT TEST FAILS
------------------
The format changed. That is either a bug, or a deliberate v2 of the file
format — in which case the correct move is to add a NEW fixture alongside this
one and teach open_file_envelope to read both, NOT to regenerate this file.
Regenerating it makes the test pass and destroys the only evidence that
anything changed.

The filename deliberately avoids the names in the repo's root .gitignore, the
same way the v1 vault fixture does.
