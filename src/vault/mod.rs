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
use secrecy::SecretSlice;
use ssh_key::{PrivateKey, PublicKey};

/// SSH key types supported by ssh-vault
#[derive(Debug, PartialEq, Eq)]
pub enum SshKeyType {
    /// Ed25519 keys using X25519 Diffie-Hellman and ChaCha20-Poly1305
    Ed25519,
    /// RSA keys using RSA-OAEP and AES-256-GCM
    Rsa,
}

/// Main vault interface for encrypting and decrypting data using SSH keys
///
/// `SshVault` provides a unified interface for working with both Ed25519 and RSA
/// encryption schemes. It handles key type detection and delegates operations to
/// the appropriate underlying implementation.
pub struct SshVault {
    vault: Box<dyn Vault>,
}

impl SshVault {
    /// Creates a new vault instance with the specified key type
    ///
    /// # Arguments
    ///
    /// * `key_type` - The SSH key type (Ed25519 or RSA)
    /// * `public` - Optional public key for encryption operations
    /// * `private` - Optional private key for decryption operations
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key type doesn't match the provided keys
    /// - Both public and private keys are provided (only one should be provided)
    /// - The keys are invalid or encrypted without proper decryption
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ssh_vault::vault::{SshVault, SshKeyType};
    /// use ssh_key::PublicKey;
    /// use std::path::Path;
    ///
    /// # fn main() -> anyhow::Result<()> {
    /// let public_key = PublicKey::read_openssh_file(Path::new("id_ed25519.pub"))?;
    /// let vault = SshVault::new(&SshKeyType::Ed25519, Some(public_key), None)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Encrypts data and creates a vault
    ///
    /// # Arguments
    ///
    /// * `password` - Secret password for encrypting the data
    /// * `data` - Mutable byte slice to encrypt (will be zeroed after encryption)
    ///
    /// # Returns
    ///
    /// Returns the vault as a formatted string that can be stored or transmitted.
    /// The format includes the algorithm, fingerprint, and encrypted payload.
    ///
    /// # Security
    ///
    /// The input `data` is zeroed after encryption to prevent sensitive data
    /// from remaining in memory.
    pub fn create(&self, password: SecretSlice<u8>, data: &mut [u8]) -> Result<String> {
        self.vault.create(password, data)
    }

    /// Decrypts and views vault contents
    ///
    /// # Arguments
    ///
    /// * `password` - Encrypted password bytes from the vault
    /// * `data` - Encrypted data bytes from the vault
    /// * `fingerprint` - Expected key fingerprint for verification
    ///
    /// # Returns
    ///
    /// Returns the decrypted data as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The fingerprint doesn't match the private key
    /// - Decryption fails (wrong key or corrupted data)
    /// - The decrypted data is not valid UTF-8
    pub fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String> {
        self.vault.view(password, data, fingerprint)
    }
}

/// Trait defining the vault operations for different key types
pub trait Vault {
    /// Creates a new vault instance with the given keys
    fn new(public: Option<PublicKey>, private: Option<PrivateKey>) -> Result<Self>
    where
        Self: Sized;

    /// Encrypts data and creates a vault string
    fn create(&self, password: SecretSlice<u8>, data: &mut [u8]) -> Result<String>;

    /// Decrypts vault contents
    fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{
        Vault, crypto, parse, ssh::decrypt_private_key, ssh::ed25519::Ed25519Vault,
        ssh::rsa::RsaVault,
    };
    use secrecy::{SecretSlice, SecretString};
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

        let password: SecretSlice<u8> = crypto::gen_password()?;

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

        let password: SecretSlice<u8> = crypto::gen_password()?;

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
            let password: SecretSlice<u8> = crypto::gen_password()?;

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
                private_key =
                    decrypt_private_key(&private_key, Some(SecretString::from(test.passphrase)))?;
            }

            let key_type = find::key_type(&private_key.algorithm())?;

            let v = SshVault::new(&key_type, None, Some(private_key))?;

            let vault = v.view(&password, &data, &fingerprint)?;

            assert_eq!(vault, SECRET);
        }
        Ok(())
    }
}
