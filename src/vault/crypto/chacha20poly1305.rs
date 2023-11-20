use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305,
};
use secrecy::{ExposeSecret, Secret};

pub struct ChaCha20Poly1305Crypto {
    key: Secret<[u8; 32]>,
}

impl super::Crypto for ChaCha20Poly1305Crypto {
    fn new(key: Secret<[u8; 32]>) -> Self {
        Self { key }
    }

    // Encrypts data with a key and a fingerprint
    fn encrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = ChaCha20Poly1305::new(self.key.expose_secret().into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: data,
            aad: fingerprint,
        };

        cipher.encrypt(&nonce, payload).map_or_else(
            |_| Err(anyhow!("Failed to encrypt data")),
            |ciphertext| {
                let mut encrypted_data = nonce.to_vec();
                encrypted_data.extend_from_slice(&ciphertext);
                Ok(encrypted_data)
            },
        )
    }

    // Decrypts data with a key and a fingerprint
    fn decrypt(&self, data: &[u8], fingerprint: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = ChaCha20Poly1305::new(self.key.expose_secret().into());
        let nonce = &data[..12];
        let ciphertext = &data[12..];
        let decrypted_data = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: fingerprint,
                },
            )
            .map_err(|err| anyhow!("Error decrypting password: {}", err))?;

        Ok(decrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::Crypto;
    use rand::{rngs::OsRng, RngCore};
    use std::collections::HashSet;

    const TEST_DATA: &str = "The quick brown fox jumps over the lazy dog";
    const FINGERPRINT: &str = "SHA256:hgIL5fEHz5zuOWY1CDlUuotdaUl4MvYG7vAgE4q4TzM";

    #[test]
    fn test_chacha20poly1305() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = Secret::new(password);

        let crypto = ChaCha20Poly1305Crypto::new(key);

        let encrypted_data = crypto
            .encrypt(TEST_DATA.as_bytes(), FINGERPRINT.as_bytes())
            .unwrap();
        let decrypted_data = crypto
            .decrypt(&encrypted_data, FINGERPRINT.as_bytes())
            .unwrap();

        assert_eq!(TEST_DATA.as_bytes(), decrypted_data);
    }

    #[test]
    fn test_chacha20poly1305_wrong_fingerprint() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = Secret::new(password);

        let crypto = ChaCha20Poly1305Crypto::new(key);

        let encrypted_data = crypto
            .encrypt(TEST_DATA.as_bytes(), FINGERPRINT.as_bytes())
            .unwrap();
        let decrypted_data = crypto.decrypt(&encrypted_data, b"SHA256:invalid_fingerprint");

        assert!(decrypted_data.is_err());
    }

    #[test]
    fn test_chacha20poly1305_rand() {
        let mut unique_keys = HashSet::new();

        for _ in 0..1000 {
            let mut rng = OsRng;
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);

            // Insert the key into the HashSet
            let is_duplicate = !unique_keys.insert(key_bytes.clone());

            // Check if it's a duplicate and assert
            if is_duplicate {
                assert!(false, "Duplicate key found")
            }

            let key = Secret::new(key_bytes);
            let crypto = ChaCha20Poly1305Crypto::new(key);

            // Generate random data
            let mut data = vec![0u8; 300];
            rng.fill_bytes(&mut data);

            // Generate random fingerprint
            let mut fingerprint = vec![0u8; 100];
            rng.fill_bytes(&mut fingerprint);

            let encrypted_data = crypto.encrypt(&data, &fingerprint).unwrap();
            let decrypted_data = crypto.decrypt(&encrypted_data, &fingerprint).unwrap();
            assert_eq!(data, decrypted_data);
        }
    }
}
