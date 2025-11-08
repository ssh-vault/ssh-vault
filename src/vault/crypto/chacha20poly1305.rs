use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use secrecy::{ExposeSecret, SecretSlice};

pub struct ChaCha20Poly1305Crypto {
    key: SecretSlice<u8>,
}

impl super::Crypto for ChaCha20Poly1305Crypto {
    fn new(key: SecretSlice<u8>) -> Self {
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
        // Validate data length before slicing
        if data.len() < 12 {
            return Err(anyhow!(
                "Invalid encrypted data: too short (expected at least 12 bytes, got {})",
                data.len()
            ));
        }

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
    use rand::{RngCore, rngs::OsRng};
    use std::collections::HashSet;

    const TEST_DATA: &str = "The quick brown fox jumps over the lazy dog";
    const FINGERPRINT: &str = "SHA256:hgIL5fEHz5zuOWY1CDlUuotdaUl4MvYG7vAgE4q4TzM";

    #[test]
    fn test_chacha20poly1305() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = SecretSlice::new(password.into());

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
        let key = SecretSlice::new(password.into());

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

            let key = SecretSlice::new(key_bytes.into());
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

    #[test]
    fn test_chacha20poly1305_decrypt_empty_data() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = SecretSlice::new(password.into());
        let crypto = ChaCha20Poly1305Crypto::new(key);

        let result = crypto.decrypt(&[], FINGERPRINT.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_chacha20poly1305_decrypt_short_data() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = SecretSlice::new(password.into());
        let crypto = ChaCha20Poly1305Crypto::new(key);

        // Test with various short lengths
        for len in 1..12 {
            let short_data = vec![0u8; len];
            let result = crypto.decrypt(&short_data, FINGERPRINT.as_bytes());
            assert!(result.is_err(), "Should fail with {} bytes", len);
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("too short"),
                "Error message should mention 'too short', got: {}",
                err_msg
            );
            assert!(
                err_msg.contains(&len.to_string()),
                "Error message should mention length {}",
                len
            );
        }
    }

    #[test]
    fn test_chacha20poly1305_decrypt_exact_minimum() {
        let mut password = [0_u8; 32];
        OsRng.fill_bytes(&mut password);
        let key = SecretSlice::new(password.into());
        let crypto = ChaCha20Poly1305Crypto::new(key);

        // 12 bytes is minimum (nonce only, no ciphertext)
        let data = vec![0u8; 12];
        let result = crypto.decrypt(&data, FINGERPRINT.as_bytes());
        // Should not panic, but will fail authentication
        assert!(result.is_err());
    }
}
