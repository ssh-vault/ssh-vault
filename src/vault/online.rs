use anyhow::Result;
use base58::ToBase58;
use ssh_key::{HashAlg, PublicKey};
use std::fmt::Write;

/// Build the URL for retrieving a generated private key helper.
///
/// # Errors
///
/// Returns an error if the URL cannot be formatted.
pub fn get_private_key_id(key: &PublicKey, user: &str) -> Result<String> {
    match user {
        "new" => {
            let fingerprint = key.fingerprint(HashAlg::Sha256);
            let mut url = String::from("https://ssh-keys.online/key/");
            write!(url, "{}", fingerprint.as_bytes().to_base58())?;
            Ok(url)
        }
        _ => Ok(String::new()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ssh_key::PublicKey;

    #[test]
    fn test_get_private_key_id() {
        let key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIlI7XymEyB/xiPQGEuiIzt7z5VDNDzuYpr3v6+hbyDN",
        )
        .unwrap();
        let id = get_private_key_id(&key, "new").unwrap();
        assert_eq!(
            id,
            "https://ssh-keys.online/key/59fKS1A4ZEQysHCbWSKUkR4n3a9pfN8g8BLwrp1eVJis"
        );
    }

    #[test]
    fn test_get_private_key_id_random_user() {
        let key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIlI7XymEyB/xiPQGEuiIzt7z5VDNDzuYpr3v6+hbyDN",
        )
        .unwrap();
        let id = get_private_key_id(&key, "random").unwrap();
        assert_eq!(id, "");
    }
}
