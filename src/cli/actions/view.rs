use crate::cli::actions::Action;
use crate::vault::{dio, find, parse, ssh::decrypt_private_key, SshVault};
use anyhow::Result;
use std::io::{Read, Write};

pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::View {
            key,
            output,
            vault,
            passphrase,
        } => {
            let mut data = String::new();

            // setup Reader(input) and Writer (output)
            let (mut input, mut output) = dio::setup_io(vault, output)?;

            input.read_to_string(&mut data)?;

            // parse vault
            let (key_type, fingerprint, password, data) = parse(&data)?;

            // find the private_key using the vault header AES256 or CHACHA20-POLY1305
            let mut private_key = find::private_key_type(key, key_type)?;

            // decrypt private_key if encrypted
            if private_key.is_encrypted() {
                private_key = decrypt_private_key(&private_key, passphrase)?;
            }

            // RSA or ED25519
            let key_type = find::key_type(&private_key.algorithm())?;

            let vault = SshVault::new(&key_type, None, Some(private_key))?;

            let data = vault.view(&password, &data, &fingerprint)?;

            output.write_all(data.as_bytes())?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
