# Frozen vault fixtures — DO NOT REGENERATE

The `.vault` files in this directory are wire-format regression fixtures.
They were encrypted once with ssh-vault 1.3.0 (the release *before* the
dalek 3.0 upgrade) and must **never** be regenerated, re-encrypted, or edited.

They are decrypted on every test run by `test_regression_ed25519_frozen_vault`
and `test_regression_rsa_frozen_vault` in `src/vault/mod.rs`, which assert the
exact original plaintext. Because decryption re-runs the full key-derivation
chain (X25519/HKDF/ChaCha20-Poly1305 and RSA-OAEP/AES-256-GCM), these tests
fail if any code or dependency change alters the crypto output — i.e. exactly
when vaults created by earlier releases would stop decrypting for real users.

If these tests turn red:

- **The code is broken, not the fixtures.** Fix or revert the change that
  broke them. Regenerating the files would hide a user-facing data-loss bug.
- The only exception is a *deliberate* new vault format: keep these fixtures
  and their tests passing (old vaults must still decrypt) and add new
  fixtures for the new format alongside them.

The fixtures decrypt with the test-only private keys `test_data/ed25519` and
`test_data/id_rsa`. Expected plaintext:
`ssh-vault regression fixture: do not regenerate this file`
