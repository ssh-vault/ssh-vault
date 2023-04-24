use crate::cli::actions::Action;
use crate::{
    tools,
    vault::{crypto, find, parse, ssh::decrypt_private_key, SshVault},
};
use anyhow::Result;
use secrecy::Secret;
use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::Command,
};
use tempfile::Builder;

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
            let mut data = String::new();

            // read vault
            let path = PathBuf::from(vault);
            let mut file = fs::File::open(&path)?;
            file.read_to_string(&mut data)?;

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

            // create vault
            let vault = SshVault::new(&key_type, None, Some(private_key))?;

            // decrypt vault
            let data = vault.view(&password, &data, &fingerprint)?;

            // write to temp file
            let file = Builder::new()
                .prefix(".vault-")
                .suffix(".ssh")
                .tempfile_in(tools::get_home()?)?;

            // write data to the tempfile
            file.as_file().write_all(data.as_bytes())?;

            // open the file in the editor
            let editor = env::var("EDITOR").unwrap_or_else(|_| String::from("vi"));

            let status = Command::new(editor).arg(file.path()).status()?;
            if !status.success() {
                return Err(anyhow::anyhow!("Editor exited with non-zero status code",));
            }

            let data = fs::read(file.path())?;

            let _ = file_shred::shred_file(file.path());

            // generate password (32 rand chars)
            let password: Secret<[u8; 32]> = crypto::gen_password()?;

            let out = vault.create(password, &data)?;
            let mut file = fs::File::create(path)?;
            file.write_all(out.as_bytes())?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
