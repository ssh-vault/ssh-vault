# Changelog

## 1.3.3
* cargo update for the current Rust 1.97-compatible dependency set
* avoid CodeQL false positives for the ed25519 HKDF salt by building it directly from public key bytes (vault format unchanged)
* add explicit read-only GitHub Actions token permissions to satisfy code-scanning workflow findings

## 1.3.1
* bump `ed25519-dalek` and `x25519-dalek` to 3.0 (`curve25519-dalek` 5.0, `rand_core` 0.10; vault format unchanged)
* build ed25519 verifying keys from raw key bytes, decoupling from `ssh-key`'s internal dalek version
* keep the `zeroize` feature enabled for `ssh-key`'s internal `ed25519-dalek` 2.x (feature unification no longer covered it after the direct dependency moved to 3.0)
* add wire-format regression tests: vault fixtures frozen at 1.3.0 in `test_data/regression/` guard against upgrades breaking decryption of existing vaults
* fix misleading "Invalid key type" error when constructing an `Ed25519Vault` from an encrypted private key (now reports "Private key is encrypted")

## 1.3.0
* security: fix editor temp-file scrub that appended zeros instead of overwriting the plaintext
* security: create `view -o` output and the key cache with owner-only permissions (0600/0700) and truncate stale bytes
* security: zeroize derived keys and decrypted secret buffers
* bump `aes-gcm` and `chacha20poly1305` to 0.11 (AEAD API migration; vault format unchanged)
* cargo update

## 1.2.14
* replace the Homebrew release action with `brew bump-formula-pr` for official Homebrew core PRs
* cargo update to refresh dependencies and fix `RUSTSEC-2026-0185`

## 1.2.13
* build and release the `aarch64-unknown-linux-musl` tarball alongside the existing release archives

## 1.2.12
* build `.deb` and `.rpm` packages for aarch64 (ARM64) on a native ARM runner, alongside the existing x86_64 packages
* bump `codecov/codecov-action` to v7
* cargo update for the current Rust-compatible dependency set

## 1.2.8
* add RPM and Debian package metadata
* attach generated `.rpm` and `.deb` packages to GitHub releases
* refresh PackageCloud distribution targets
* bump `rpassword` to 7.5

## 1.2.6
* cargo update for the current Rust 1.95-compatible dependency set
* clippy compatibility fixes in cache expiration and output metadata checks

## 1.2.5
* updated direct randomness usage to `rand 0.10` while keeping compatibility with current `rsa` / `ssh-key` releases
* refreshed GitHub Actions dependencies to current major versions

## 1.2.0
* replaced OpenSSL with rustls for TLS
* clippy improvements

## 1.1.4
* cargo update: bump home to 0.5.12, hex-literal to 1.1.0

## 1.1.0
* using `rsa::RsaPrivatekey::from_components` to create the private key from `ssh_key::PrivateKey::read_openssh_file`
* edition 2024

## 1.0.13
* bump versions, cargo update

## 1.0.7
* removed atty in favor of [std::io::IsTerminal](https://github.com/ssh-vault/ssh-vault/security/dependabot/7)
* using Zeroize

## 1.0.6
* display --help if no arguments are present
* Check if the path to save the vault is empty (prevent overwriting existing files)
* show examples only per command help not in main

## 1.0.5
* help templates/examples
* support for .config/ssh-vault/config.yml

## 1.0.4
* Added option `--input` to create a vault from an existing file

## 1.0.2
* Added option `--json` when creating a vault
* easy share using `echo "secret" | ssh-vault c -u new | pbcopy` copy & page to share the secret

## 1.0.0
* Support for ed25519 keys
* Legacy keys header (`-----BEGIN RSA PRIVATE KEY-----`) need to be updated using `ssh-keygen -p`
* moving to rust 🦀

## 0.12.8
* Support encrypted openssh private keys [#50](https://github.com/ssh-vault/ssh-vault/pull/50)

## 0.12.6
* Using crypto/ssh to match OpenSSH private key format (openssh-key-v1)

## 0.12.5
* Updated dependencies, thanks @iwittkau

## 0.12.4
* Improved lint
* Update GetPasswordPrompt message [#28](https://github.com/ssh-vault/ssh-vault/pull/28)
