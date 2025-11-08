use crate::vault::{
    Vault, crypto, crypto::Crypto, crypto::chacha20poly1305::ChaCha20Poly1305Crypto,
};
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::{Digest, Sha512};
use ssh_key::{
    HashAlg, PrivateKey, PublicKey,
    private::{Ed25519PrivateKey, KeypairData},
    public::KeyData,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct Ed25519Vault {
    montgomery_key: X25519PublicKey,
    private_key: Option<Ed25519PrivateKey>,
    public_key: PublicKey,
}

impl Vault for Ed25519Vault {
    fn new(public: Option<PublicKey>, private: Option<PrivateKey>) -> Result<Self> {
        match (public, private) {
            (Some(public), None) => match public.key_data() {
                KeyData::Ed25519(key_data) => {
                    let public_key = ed25519_dalek::VerifyingKey::try_from(key_data)
                        .context("Could not load key")?;
                    let montgomery_key: X25519PublicKey =
                        public_key.to_montgomery().to_bytes().into();

                    Ok(Self {
                        montgomery_key,
                        private_key: None,
                        public_key: public,
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for Ed25519Vault")),
            },
            (None, Some(private)) => match private.key_data() {
                KeypairData::Ed25519(key_data) => {
                    if private.is_encrypted() {
                        return Err(anyhow::anyhow!("Private key is encrypted"));
                    }
                    let public_key = private.public_key().clone();
                    let verifying_key = ed25519_dalek::VerifyingKey::try_from(key_data.public)?;
                    let montgomery_key: X25519PublicKey =
                        verifying_key.to_montgomery().to_bytes().into();

                    Ok(Self {
                        montgomery_key,
                        private_key: Some(key_data.private.clone()),
                        public_key,
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for Ed25519Vault")),
            },
            _ => Err(anyhow::anyhow!("Missing public and private key")),
        }
    }

    fn create(&self, password: SecretSlice<u8>, data: &mut [u8]) -> Result<String> {
        let crypto = ChaCha20Poly1305Crypto::new(password.clone());

        // get the fingerprint of the public key
        let fingerprint = self.public_key.fingerprint(HashAlg::Sha256);

        // encrypt the data with the password
        let encrypted_data = crypto.encrypt(data, fingerprint.as_bytes())?;

        // zeroize data
        data.zeroize();

        // generate an ephemeral key pair
        let e_secret = EphemeralSecret::random();
        let e_public: X25519PublicKey = (&e_secret).into();

        let shared_secret: StaticSecret =
            (*e_secret.diffie_hellman(&self.montgomery_key).as_bytes()).into();

        // the salt is the concatenation of the
        // ephemeral public key and the receiver's public key
        let mut salt = [0; 64];
        salt[..32].copy_from_slice(e_public.as_bytes());
        salt[32..].copy_from_slice(self.montgomery_key.as_bytes());

        let enc_key = crypto::hkdf(&salt, fingerprint.as_bytes(), shared_secret.as_bytes())?;

        // encrypt the password with the derived key
        let crypto = ChaCha20Poly1305Crypto::new(SecretSlice::new(enc_key.into()));
        let encrypted_password =
            crypto.encrypt(password.expose_secret(), fingerprint.as_bytes())?;

        // create vault payload
        Ok(format!(
            "SSH-VAULT;CHACHA20-POLY1305;{};{};{};{}",
            fingerprint,
            Base64::encode_string(e_public.as_bytes()),
            Base64::encode_string(&encrypted_password),
            Base64::encode_string(&encrypted_data)
        )
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n"))
    }

    fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String> {
        let get_fingerprint = self.public_key.fingerprint(HashAlg::Sha256);

        if get_fingerprint.to_string() != fingerprint {
            return Err(anyhow::anyhow!("Fingerprint mismatch, use correct key"));
        }

        match &self.private_key {
            Some(private_key) => {
                // Validate password length before slicing
                if password.len() < 32 {
                    return Err(anyhow::anyhow!(
                        "Invalid password data: too short (expected at least 32 bytes, got {})",
                        password.len()
                    ));
                }

                // extract the ephemeral public key
                let mut epk: [u8; 32] = [0; 32];
                epk.copy_from_slice(&password[0..32]);

                // extract the encrypted password
                let encrypted_password = &password[32..];

                // decode the ephemeral public key
                let epk = X25519PublicKey::from(epk);

                // generate the static secret and public key
                let sk: StaticSecret = {
                    let mut sk = [0u8; 32];
                    sk.copy_from_slice(&Sha512::digest(private_key.as_ref())[0..32]);
                    sk.into()
                };
                let pk = X25519PublicKey::from(&sk);

                // generate the shared secret
                let shared_secret: StaticSecret = (*sk.diffie_hellman(&epk).as_bytes()).into();

                let mut salt = [0; 64];
                salt[..32].copy_from_slice(epk.as_bytes());
                salt[32..].copy_from_slice(pk.as_bytes());

                let enc_key =
                    crypto::hkdf(&salt, get_fingerprint.as_bytes(), shared_secret.as_bytes())?;

                // use the enc_key to decrypt the password
                let crypto = ChaCha20Poly1305Crypto::new(SecretSlice::new(enc_key.into()));

                let password = crypto.decrypt(encrypted_password, get_fingerprint.as_bytes())?;

                // Validate decrypted password length before slicing
                if password.len() < 32 {
                    return Err(anyhow::anyhow!(
                        "Invalid decrypted password: too short (expected at least 32 bytes, got {})",
                        password.len()
                    ));
                }

                let mut p: [u8; 32] = [0; 32];
                p.copy_from_slice(&password[0..32]);

                // decrypt the data with the derived key
                let crypto = ChaCha20Poly1305Crypto::new(SecretSlice::new(p.into()));

                let out = crypto.decrypt(data, get_fingerprint.as_bytes())?;
                Ok(String::from_utf8(out)?)
            }
            None => Err(anyhow::anyhow!("Private key is required to view vault")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ED25519_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILr6U238r+PD4rSvZAu/RNJfaNgzglzSvdLKA28h4kB1";

    #[test]
    fn test_ed25519_view_short_password_data() {
        // Create an Ed25519 vault with a public key
        let public_key = TEST_ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();
        let vault = Ed25519Vault::new(Some(public_key), None).unwrap();

        // Test with password data shorter than 32 bytes
        for len in 0..32 {
            let short_password = vec![0u8; len];
            let data = vec![0u8; 50];
            let fingerprint = "SHA256:test";

            let result = vault.view(&short_password, &data, fingerprint);
            assert!(result.is_err(), "Should fail with {} bytes", len);
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("too short") || err_msg.contains("Fingerprint mismatch"),
                "Error should mention 'too short' or fingerprint mismatch, got: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_ed25519_view_empty_password() {
        let public_key = TEST_ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();
        let vault = Ed25519Vault::new(Some(public_key), None).unwrap();

        let result = vault.view(&[], &[0u8; 50], "SHA256:test");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too short") || err_msg.contains("Fingerprint mismatch"),
            "Error should mention issue, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_ed25519_new_with_valid_public_key() {
        let public_key = TEST_ED25519_PUBLIC_KEY.parse::<PublicKey>().unwrap();
        let result = Ed25519Vault::new(Some(public_key), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_new_without_keys() {
        let result = Ed25519Vault::new(None, None);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Missing public and private key"));
        }
    }
}
