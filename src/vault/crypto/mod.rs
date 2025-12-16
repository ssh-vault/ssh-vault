pub mod aes256;
pub mod chacha20poly1305;

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use rsa::sha2;
use secrecy::SecretSlice;
use sha2::Sha256;

/// Trait defining cryptographic operations for vault encryption
///
/// This trait provides a common interface for different authenticated encryption
/// algorithms used in ssh-vault (AES-256-GCM and ChaCha20-Poly1305).
pub trait Crypto {
    /// Creates a new crypto instance with the given key
    fn new(key: SecretSlice<u8>) -> Self;

    /// Encrypts data using authenticated encryption with associated data (AEAD)
    ///
    /// # Arguments
    ///
    /// * `data` - The plaintext data to encrypt
    /// * `fingerprint` - Additional authenticated data (key fingerprint)
    ///
    /// # Returns
    ///
    /// Returns the encrypted data including nonce/IV prepended to the ciphertext
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    fn encrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts data using authenticated encryption with associated data (AEAD)
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted data including nonce/IV
    /// * `fingerprint` - Additional authenticated data for verification
    ///
    /// # Returns
    ///
    /// Returns the decrypted plaintext data
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or decryption is unsuccessful
    fn decrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>>;
}

/// Generates a cryptographically secure random password
///
/// Creates a 32-byte (256-bit) random password suitable for vault encryption.
///
/// # Returns
///
/// Returns a secret slice containing the random password
///
/// # Security
///
/// Uses the operating system's cryptographically secure random number generator
///
/// # Errors
///
/// Returns an error if secure random bytes cannot be generated.
pub fn gen_password() -> Result<SecretSlice<u8>> {
    let mut password = [0_u8; 32];
    OsRng.fill_bytes(&mut password);
    Ok(SecretSlice::new(password.into()))
}

/// HMAC-based Key Derivation Function (HKDF) using SHA-256
///
/// Derives a 256-bit key from input keying material using HKDF-SHA256.
///
/// # Arguments
///
/// * `salt` - Salt value for the KDF (should be 64 bytes for ed25519 vaults)
/// * `info` - Context and application specific information (fingerprint)
/// * `ikm` - Input keying material (shared secret from key exchange)
///
/// # Returns
///
/// Returns a 32-byte derived key
///
/// # Security
///
/// HKDF provides cryptographic strength key derivation from potentially weak
/// shared secrets. The salt should be unique per encryption operation.
///
/// # Errors
///
/// Returns an error if key expansion fails.
pub fn hkdf(salt: &[u8], info: &[u8], ikm: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let mut output_key_material = [0; 32];

    // Expand the input keying material into an output keying material of 32 bytes
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut output_key_material)
        .map_err(|err| anyhow!("Error during HKDF expansion: {err}"))?;

    Ok(output_key_material)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use secrecy::ExposeSecret;

    #[test]
    fn test_gen_password() {
        let password = gen_password().unwrap();
        assert_eq!(password.expose_secret().len(), 32);
    }

    #[test]
    fn test_hkdf() {
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let salt = hex!("000102030405060708090a0b0c");
        let expected = hex!(
            "
                3cb25f25faacd57a90434f64d0362f2a
                2d2d0a90cf1a5a4c5db02d56ecc4c5bf
                34007208d5b887185865
            "
        );
        let okm = hkdf(&salt, &info, &ikm).unwrap();
        assert_eq!(okm[..], expected[..32]);
    }
}
