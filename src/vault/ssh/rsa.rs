use crate::vault::{
    crypto::aes256::Aes256Crypto, crypto::Crypto, fingerprint::md5_fingerprint, Vault,
};
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use ssh_key::{private::KeypairData, public::KeyData, PrivateKey, PublicKey};

pub struct RsaVault {
    public_key: RsaPublicKey,
    private_key: Option<RsaPrivateKey>,
}

impl Vault for RsaVault {
    fn new(public: Option<PublicKey>, private: Option<PrivateKey>) -> Result<Self> {
        match (public, private) {
            (Some(public), None) => match public.key_data() {
                KeyData::Rsa(key_data) => {
                    let public_key =
                        RsaPublicKey::try_from(key_data).context("Could not load key")?;
                    Ok(Self {
                        public_key,
                        private_key: None,
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for RsaVault")),
            },

            (None, Some(private)) => match private.key_data() {
                KeypairData::Rsa(key_data) => {
                    if private.is_encrypted() {
                        return Err(anyhow::anyhow!("Private key is encrypted"));
                    }
                    let private_key = RsaPrivateKey::try_from(key_data)?;
                    let public_key = private_key.to_public_key();
                    Ok(Self {
                        public_key,
                        private_key: Some(private_key),
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for RsaVault")),
            },
            (Some(_), Some(_)) => Err(anyhow::anyhow!(
                "Only one of public and private key is required"
            )),
            _ => Err(anyhow::anyhow!("Missing public and private key")),
        }
    }

    fn create(&self, password: Secret<[u8; 32]>, data: &[u8]) -> Result<String> {
        let crypto = Aes256Crypto::new(password.clone());

        let fingerprint = md5_fingerprint(&self.public_key)?;

        let encrypted_data = crypto.encrypt(data, fingerprint.as_bytes())?;

        let encrypted_password =
            self.public_key
                .encrypt(&mut OsRng, Oaep::new::<Sha256>(), password.expose_secret())?;

        // create vault payload
        let payload = format!(
            "{};{}",
            Base64::encode_string(&encrypted_password),
            Base64::encode_string(&encrypted_data)
        )
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");

        Ok(format!("SSH-VAULT;AES256;{fingerprint}\n{payload}"))
    }

    fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String> {
        let get_fingerprint = md5_fingerprint(&self.public_key)?;

        if get_fingerprint != fingerprint {
            return Err(anyhow::anyhow!("Fingerprint mismatch, use correct key"));
        }

        match &self.private_key {
            Some(private_key) => {
                let password: Secret<[u8; 32]> = Secret::new(
                    private_key
                        .decrypt(Oaep::new::<Sha256>(), password)?
                        .try_into()
                        .map_err(|_| anyhow::Error::msg("Invalid password"))?,
                );

                let crypto = Aes256Crypto::new(password);

                let out = crypto.decrypt(data, fingerprint.as_bytes())?;
                Ok(String::from_utf8(out)?)
            }
            None => Err(anyhow::anyhow!("Private key is required to view vault")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use anyhow::Result;
    use ssh_key::{PrivateKey, PublicKey};
    use std::path::Path;

    #[test]
    fn test_rsa_vault_using_both_keys() -> Result<()> {
        let public_key_file = Path::new("test_data/id_rsa.pub");
        let private_key_file = Path::new("test_data/id_rsa");
        let public_key = PublicKey::read_openssh_file(&public_key_file)?;
        let private_key = PrivateKey::read_openssh_file(&private_key_file)?;
        let vault = RsaVault::new(Some(public_key), Some(private_key));
        assert_eq!(vault.is_err(), true);
        Ok(())
    }
}
