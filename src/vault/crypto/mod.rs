pub mod aes256;
pub mod chacha20poly1305;

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rsa::sha2;
use secrecy::SecretSlice;
use sha2::Sha256;

// Define a trait for cryptographic algorithms
pub trait Crypto {
    fn new(key: SecretSlice<u8>) -> Self;
    fn encrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>>;
}

// Generate a random password
pub fn gen_password() -> Result<SecretSlice<u8>> {
    let mut password = [0_u8; 32];
    OsRng.fill_bytes(&mut password);
    Ok(SecretSlice::new(password.into()))
}

// HMAC key derivation function
pub fn hkdf(salt: &[u8], info: &[u8], ikm: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let mut output_key_material = [0; 32];

    // Expand the input keying material into an output keying material of 32 bytes
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut output_key_material)
        .map_err(|err| anyhow!("Error during HKDF expansion: {}", err))?;

    Ok(output_key_material)
}

#[cfg(test)]
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
        assert_eq!(okm[..], expected[..32])
    }
}
