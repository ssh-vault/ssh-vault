use crate::cli::actions::Action;
use crate::vault::{find, parse, ssh::decrypt_private_key, SshVault};
use anyhow::{anyhow, Result};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::View {
            key,
            output,
            vault,
            passphrase,
        } => {
            let mut data = String::new();

            // isatty returns false if there's something in stdin.
            let input_stdin = !atty::is(atty::Stream::Stdin);

            if input_stdin {
                std::io::stdin().read_to_string(&mut data)?;
            } else if let Some(vault) = &vault {
                let path = PathBuf::from(vault);
                let mut file = File::open(path)?;
                file.read_to_string(&mut data)?;
            } else {
                return Err(anyhow!("No vault provided"));
            }

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

            if let Some(output) = output {
                let path = PathBuf::from(output);
                let mut file = File::create(path)?;
                file.write_all(data.as_bytes())?;
            } else {
                print!("{data}");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
