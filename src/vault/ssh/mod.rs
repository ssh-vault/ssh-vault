pub mod ed25519;
pub mod rsa;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use ssh_key::PrivateKey;

/// Decrypts a private key with a password.
///
/// # Errors
///
/// Returns an error if prompting for the passphrase fails or the key cannot be
/// decrypted.
pub fn decrypt_private_key(key: &PrivateKey, password: Option<SecretString>) -> Result<PrivateKey> {
    let password = match password {
        Some(password) => password,
        None => SecretString::from(rpassword::prompt_password("Enter ssh key passphrase: ")?),
    };

    // Decrypt the private key
    key.decrypt(password.expose_secret())
        .context("Failed to decrypt private key, wrong password?")
}
