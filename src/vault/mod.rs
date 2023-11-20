pub mod crypto;
pub mod dio;
pub mod find;
pub mod fingerprint;
pub mod online;
pub mod remote;
pub mod ssh;

pub mod parse;
pub use self::parse::parse;

use anyhow::Result;
use secrecy::Secret;
use ssh_key::{PrivateKey, PublicKey};

#[derive(Debug, PartialEq, Eq)]
pub enum SshKeyType {
    Ed25519,
    Rsa,
}

pub struct SshVault {
    vault: Box<dyn Vault>,
}

impl SshVault {
    pub fn new(
        key_type: &SshKeyType,
        public: Option<PublicKey>,
        private: Option<PrivateKey>,
    ) -> Result<Self> {
        let vault = match key_type {
            SshKeyType::Ed25519 => {
                Box::new(ssh::ed25519::Ed25519Vault::new(public, private)?) as Box<dyn Vault>
            }
            SshKeyType::Rsa => {
                Box::new(ssh::rsa::RsaVault::new(public, private)?) as Box<dyn Vault>
            }
        };
        Ok(Self { vault })
    }

    pub fn create(&self, password: Secret<[u8; 32]>, data: &mut [u8]) -> Result<String> {
        self.vault.create(password, data)
    }

    pub fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String> {
        self.vault.view(password, data, fingerprint)
    }
}

pub trait Vault {
    fn new(public: Option<PublicKey>, private: Option<PrivateKey>) -> Result<Self>
    where
        Self: Sized;
    fn create(&self, password: Secret<[u8; 32]>, data: &mut [u8]) -> Result<String>;
    fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        crypto, parse, ssh::decrypt_private_key, ssh::ed25519::Ed25519Vault, ssh::rsa::RsaVault,
        Vault,
    };
    use secrecy::Secret;
    use ssh_key::PublicKey;
    use std::path::Path;

    struct Test {
        public_key: &'static str,
        private_key: &'static str,
        passphrase: &'static str,
    }

    const SECRET: &str = "Take care of your thoughts, because they will become your words. Take care of your words, because they will become your actions. Take care of your actions, because they will become your habits. Take care of your habits, because they will become your destiny";

    #[test]
    fn test_rsa_vault() -> Result<()> {
        let public_key_file = Path::new("test_data/id_rsa.pub");
        let private_key_file = Path::new("test_data/id_rsa");
        let public_key = PublicKey::read_openssh_file(&public_key_file)?;
        let private_key = PrivateKey::read_openssh_file(&private_key_file)?;

        let vault = RsaVault::new(Some(public_key), None)?;

        let password: Secret<[u8; 32]> = crypto::gen_password()?;

        let mut secret = String::from(SECRET).into_bytes();

        // not filled with zeros
        assert!(secret.iter().all(|&byte| byte != 0));

        let vault = vault.create(password, &mut secret)?;

        // filled with zeros
        assert!(secret.iter().all(|&byte| byte == 0));

        let (_key_type, fingerprint, password, data) = parse(&vault)?;

        let view = RsaVault::new(None, Some(private_key))?;

        let vault = view.view(&password, &data, &fingerprint)?;

        assert_eq!(vault, SECRET);
        Ok(())
    }

    #[test]
    fn test_ed25519_vault() -> Result<()> {
        let public_key_file = Path::new("test_data/ed25519.pub");
        let private_key_file = Path::new("test_data/ed25519");
        let public_key = PublicKey::read_openssh_file(&public_key_file)?;
        let private_key = PrivateKey::read_openssh_file(&private_key_file)?;

        let vault = Ed25519Vault::new(Some(public_key), None)?;

        let password: Secret<[u8; 32]> = crypto::gen_password()?;

        let mut secret = String::from(SECRET).into_bytes();

        // not filled with zeros
        assert!(secret.iter().all(|&byte| byte != 0));

        let vault = vault.create(password, &mut secret)?;

        // filled with zeros
        assert!(secret.iter().all(|&byte| byte == 0));

        let (_key_type, fingerprint, password, data) = parse(&vault)?;

        let view = Ed25519Vault::new(None, Some(private_key))?;

        let vault = view.view(&password, &data, &fingerprint)?;

        assert_eq!(vault, SECRET);
        Ok(())
    }

    #[test]
    fn test_vault() -> Result<()> {
        let tests = [
            Test {
                public_key: "test_data/id_rsa.pub",
                private_key: "test_data/id_rsa",
                passphrase: "",
            },
            Test {
                public_key: "test_data/ed25519.pub",
                private_key: "test_data/ed25519",
                passphrase: "",
            },
            Test {
                public_key: "test_data/id_rsa_password.pub",
                private_key: "test_data/id_rsa_password",
                // echo -n "ssh-vault" | openssl dgst -sha1
                passphrase: "85990de849bb89120ea3016b6b76f6d004857cb7",
            },
            Test {
                public_key: "test_data/ed25519_password.pub",
                private_key: "test_data/ed25519_password",
                // echo -n "ssh-vault" | openssl dgst -sha1
                passphrase: "85990de849bb89120ea3016b6b76f6d004857cb7",
            },
        ];

        for test in tests.iter() {
            // create
            let public_key = test.public_key.to_string();
            let public_key = find::public_key(Some(public_key))?;
            let key_type = find::key_type(&public_key.algorithm())?;
            let v = SshVault::new(&key_type, Some(public_key), None)?;
            let password: Secret<[u8; 32]> = crypto::gen_password()?;

            let mut secret = String::from(SECRET).into_bytes();

            // not filled with zeros
            assert!(secret.iter().all(|&byte| byte != 0));

            let vault = v.create(password, &mut secret)?;

            // filled with zeros
            assert!(secret.iter().all(|&byte| byte == 0));

            // view
            let private_key = test.private_key.to_string();
            let (key_type, fingerprint, password, data) = parse(&vault)?;
            let mut private_key = find::private_key_type(Some(private_key), key_type)?;

            if private_key.is_encrypted() {
                private_key = decrypt_private_key(
                    &private_key,
                    Some(Secret::new(test.passphrase.to_string())),
                )?;
            }
            let key_type = find::key_type(&private_key.algorithm())?;

            let v = SshVault::new(&key_type, None, Some(private_key))?;
            let vault = v.view(&password, &data, &fingerprint)?;

            assert_eq!(vault, SECRET);
        }
        Ok(())
    }
}
