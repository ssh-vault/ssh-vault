pub mod ed25519;
pub mod rsa;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, Secret};
use ssh_key::PrivateKey;

// Decrypts a private key with a password
pub fn decrypt_private_key(
    key: &PrivateKey,
    password: Option<Secret<String>>,
) -> Result<PrivateKey> {
    let password = match password {
        Some(password) => password,
        None => Secret::new(rpassword::prompt_password("Enter ssh key passphrase: ")?),
    };

    // Decrypt the private key
    key.decrypt(password.expose_secret())
        .context("Failed to decrypt private key, wrong password?")
}
