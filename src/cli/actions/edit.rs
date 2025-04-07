use crate::cli::actions::{Action, process_input};
use crate::vault::{SshVault, crypto, dio, find, parse, ssh::decrypt_private_key};
use anyhow::Result;
use secrecy::{SecretSlice, SecretString};
use std::io::{Read, Write};

/// Handle the edit action
/// # Errors
/// Will return an error if the file cannot be read or written to
pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Edit {
            key,
            vault,
            passphrase,
        } => {
            let mut vault_data = String::new();

            // set the R/W streams
            let (mut input, mut output) = dio::setup_io(Some(vault.clone()), Some(vault))?;

            // read the vault content
            input.read_to_string(&mut vault_data)?;

            // parse the vault
            let (key_type, fingerprint, password, data) = parse(&vault_data)?;

            // find the private_key using the vault header AES256 or CHACHA20-POLY1305
            let mut private_key = find::private_key_type(key, key_type)?;

            // decrypt private_key if encrypted
            if private_key.is_encrypted() {
                private_key = decrypt_private_key(&private_key, passphrase)?;
            }

            // RSA or ED25519
            let key_type = find::key_type(&private_key.algorithm())?;

            // initialize the vault
            let vault = SshVault::new(&key_type, None, Some(private_key))?;

            // decrypt the vault
            let secret = vault.view(&password, &data, &fingerprint)?;

            // store the new encrypted data
            let mut new_secret = Vec::new();

            // use the EDITOR env var to edit the existing secret
            process_input(&mut new_secret, Some(SecretString::from(secret)))?;

            // generate password (32 rand chars)
            let password: SecretSlice<u8> = crypto::gen_password()?;

            // create vault
            let out = vault.create(password, &mut new_secret)?;

            // save the vault
            output.truncate()?;
            output.write_all(out.as_bytes())?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
