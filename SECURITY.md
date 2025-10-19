# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

We take the security of ssh-vault seriously. If you discover a security vulnerability, please follow these steps:

### Private Disclosure

**DO NOT** open a public issue for security vulnerabilities.

Instead, please report security issues by emailing: [nbari@tequila.io](mailto:nbari@tequila.io)

Please include:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 90 days

## Security Measures

### Cryptographic Implementations

ssh-vault uses well-vetted cryptographic libraries:

- **AES-256-GCM**: Authenticated encryption for RSA vaults
- **ChaCha20-Poly1305**: Authenticated encryption for Ed25519 vaults
- **HKDF-SHA256**: Key derivation function
- **X25519**: Elliptic-curve Diffie-Hellman key exchange
- **RSA-OAEP**: RSA encryption with optimal asymmetric encryption padding

### Key Features

- **Secret Zeroization**: Sensitive data is zeroed from memory after use using the `zeroize` crate
- **Perfect Forward Secrecy**: Ed25519 vaults use ephemeral keys for each encryption
- **Memory Safety**: Built with Rust's memory safety guarantees
- **No Key Reuse**: Each encryption operation generates new ephemeral keys

### Dependencies

We regularly audit dependencies for known vulnerabilities:
- Automated daily security audits via GitHub Actions
- `cargo-audit` for vulnerability scanning
- `cargo-deny` for license and security policy enforcement

## Known Issues

### RUSTSEC-2023-0071: Marvin Attack on RSA (Acknowledged)

**Status**: Known and accepted risk

**Description**: The `rsa` crate (v0.9.8) has a timing side-channel vulnerability that could potentially allow key recovery through timing information observable over the network.

**Impact Assessment**:
- **Severity**: Medium (for ssh-vault's use case)
- **Attack Requirements**:
  - Network-observable timing measurements
  - Many decryption attempts (hundreds to thousands)
  - Sophisticated timing analysis equipment
- **ssh-vault's Risk Profile**: Low
  - Primarily used for local decryption (not network-exposed)
  - Single decryption attempt per vault
  - No continuous decryption service

**Mitigation Status**:
- Tracking upstream fix: https://github.com/RustCrypto/RSA/issues/19
- RustCrypto team is working on constant-time implementation
- Will upgrade when patched version is available

**Workaround**: 
- Use Ed25519 keys instead of RSA (recommended)
- Avoid using RSA vaults in network-exposed services
- Local use on non-compromised systems is safe

**Reference**: [Marvin Attack Research](https://people.redhat.com/~hkario/marvin/)

## Security Best Practices

When using ssh-vault:

1. **Use Strong SSH Keys**: Generate keys with at least 2048 bits for RSA or Ed25519
2. **Protect Private Keys**: Store private keys securely with appropriate permissions (chmod 600)
3. **Use Passphrases**: Protect private keys with strong passphrases
4. **Update Regularly**: Keep ssh-vault updated to the latest version
5. **Verify Sources**: Only download ssh-vault from official sources
6. **Prefer Ed25519**: Ed25519 keys provide better security properties than RSA

## Security Testing

### Automated Checks
- Daily vulnerability scans via `cargo-audit`
- License and dependency compliance via `cargo-deny`
- Continuous integration security checks on all PRs

### Manual Reviews
- Code review for all security-sensitive changes
- Cryptographic implementations reviewed against best practices
- Regular dependency updates and audits

## Auditing

This project has not undergone a formal third-party security audit. We welcome security researchers to review our code and report findings.

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who help improve ssh-vault's security (with permission).
