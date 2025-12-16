use crate::{
    tools,
    vault::{SshKeyType, remote},
};
use anyhow::{Context, Result, anyhow};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

/// Find key type RSA or ED25519.
///
/// # Errors
///
/// Returns an error if the algorithm is unsupported.
pub fn key_type(key: &Algorithm) -> Result<SshKeyType> {
    match key {
        Algorithm::Rsa { .. } => Ok(SshKeyType::Rsa),
        Algorithm::Ed25519 => Ok(SshKeyType::Ed25519),
        _ => Err(anyhow::anyhow!("Unsupported ssh key type")),
    }
}

/// Find private key type RSA or ED25519 based on vault header.
///
/// # Errors
///
/// Returns an error if the key type is not supported.
pub fn private_key_type(key: Option<String>, key_type: &str) -> Result<PrivateKey> {
    match key_type {
        "AES256" => private_key(key, &SshKeyType::Rsa),
        "CHACHA20-POLY1305" => private_key(key, &SshKeyType::Ed25519),
        _ => Err(anyhow!("Unsupported key type")),
    }
}

/// Load a public key from disk.
///
/// # Errors
///
/// Returns an error if no key is found or the key cannot be parsed.
pub fn public_key(key: Option<String>) -> Result<PublicKey> {
    let key: PathBuf = if let Some(key) = key {
        Path::new(&key).to_path_buf()
    } else {
        let home = tools::get_home()?;
        let rsa_pub_key = home.join(".ssh").join("id_rsa.pub");
        let ed25519_pub_key = home.join(".ssh").join("id_ed25519.pub");
        if rsa_pub_key.exists() {
            rsa_pub_key
        } else if ed25519_pub_key.exists() {
            ed25519_pub_key
        } else {
            return Err(anyhow::anyhow!("No key found"));
        }
    };

    PublicKey::read_openssh_file(&key).context("Ensure you are passing a valid openssh public key")
}

/// Load a private key from disk or URL.
///
/// # Errors
///
/// Returns an error if the key is missing, cannot be read, or is in an
/// unsupported format.
pub fn private_key(key: Option<String>, ssh_type: &SshKeyType) -> Result<PrivateKey> {
    let private_key = if let Some(key) = key {
        if key.starts_with("http://") || key.starts_with("https://") {
            remote::request(&key, true)?
        } else {
            let mut buffer = String::new();
            File::open(&key)?.read_to_string(&mut buffer)?;
            buffer
        }
    } else {
        let home = tools::get_home()?;
        let key_path = match ssh_type {
            SshKeyType::Rsa => home.join(".ssh").join("id_rsa"),
            SshKeyType::Ed25519 => home.join(".ssh").join("id_ed25519"),
        };
        if key_path.exists() {
            let mut private_key = String::new();
            File::open(key_path)?.read_to_string(&mut private_key)?;
            private_key
        } else {
            return Err(anyhow!(
                "No private key found in {}",
                home.join(".ssh").display()
            ));
        }
    };

    let private_key = private_key.trim();

    // check if it's a legacy rsa key
    if private_key.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        return Err(anyhow!(
            "Legacy RSA key not supported, use ssh-keygen -p -f <key> to convert it to openssh format"
        ));
    }

    // read openssh key and return it as a PrivateKey
    PrivateKey::from_openssh(private_key)
        .context("Ensure you are passing a valid openssh private key")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::vault::SshKeyType;
    use ssh_key::Algorithm;

    #[test]
    fn test_key_type() {
        assert_eq!(
            key_type(&Algorithm::Rsa { hash: None }).unwrap(),
            SshKeyType::Rsa
        );
        assert_eq!(key_type(&Algorithm::Ed25519).unwrap(), SshKeyType::Ed25519);
        assert!(key_type(&Algorithm::Dsa).is_err());
    }

    #[test]
    fn test_private_key_type() {
        assert!(private_key_type(Some("test_data/id_rsa".to_string()), "AES256").is_ok());
        assert!(private_key_type(Some("test_data/id_rsa".to_string()), "RSA").is_err());
        assert!(
            private_key_type(Some("test_data/ed25519".to_string()), "CHACHA20-POLY1305",).is_ok()
        );
        assert!(private_key_type(Some("test_data/ed25519".to_string()), "AES256").is_ok());
        assert_eq!(
            private_key_type(Some("test_data/ed25519".to_string()), "AES256")
                .unwrap()
                .algorithm(),
            Algorithm::Ed25519
        );
        assert_eq!(
            private_key_type(Some("test_data/id_rsa".to_string()), "CHACHA20-POLY1305",)
                .unwrap()
                .algorithm(),
            Algorithm::Rsa { hash: None }
        );
    }

    #[test]
    fn test_public_key() {
        assert!(public_key(Some("test_data/id_rsa.pub".to_string())).is_ok());
        assert!(public_key(Some("test_data/ed25519.pub".to_string())).is_ok());
    }

    #[test]
    fn test_private_key() {
        assert!(private_key(Some("test_data/id_rsa".to_string()), &SshKeyType::Rsa).is_ok());
        assert!(private_key(Some("test_data/ed25519".to_string()), &SshKeyType::Ed25519).is_ok());
    }
}
