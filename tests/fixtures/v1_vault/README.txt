v1 GOLDEN FIXTURE — DO NOT REGENERATE
======================================

These two files are byte-frozen artefacts of the v1 Fernet encryption
path (crypto.encrypt / crypto.decrypt / PBKDF2_ITERATIONS = 480_000).

  v1_vault.salt  — 16-byte PBKDF2 salt (hex: deadbeefcafebabe0102030405060708)
  v1_vault.enc   — Fernet token produced by crypto.encrypt()

They were generated once with:
  password : "v1-fixture-password-do-not-change"
  plaintext: JSON of {"FIXTURE_API_KEY": "sk-fixture-0000-not-a-real-key",
                      "FIXTURE_SECRET":  "fixture-value-do-not-use"}

tests/test_vault_format.py::test_v1_fixture_decrypts_correctly reads these
files and asserts the exact expected plaintext.  If that test starts failing
it means someone edited the v1 frozen functions (new_salt, _derive_key,
encrypt, decrypt, PBKDF2_ITERATIONS) in vault_lib/crypto.py — which is
explicitly forbidden by the module docstring.

DO NOT DELETE OR REGENERATE THESE FILES.  They are a tripwire.
The filenames are intentionally NOT "vault.enc" / "vault.salt" to avoid
being caught by the root .gitignore patterns that exclude the developer's
live vault.
