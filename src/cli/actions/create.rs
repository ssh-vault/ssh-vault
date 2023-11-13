use crate::cli::actions::Action;
use crate::{
    tools,
    vault::{crypto, find, online, remote, SshVault},
};
use anyhow::Result;
use secrecy::Secret;
use ssh_key::PublicKey;
use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::Command,
};
use tempfile::Builder;

/// Handle the create action
pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Create {
            fingerprint,
            key,
            user,
            vault,
        } => {
            // print the url from where to download the key
            let mut helper = String::new();

            let ssh_key: PublicKey = if let Some(user) = user {
                let int_key: Option<u32> = key.and_then(|s| s.parse::<u32>().ok());
                let keys = remote::get_keys(&user)?;
                let ssh_key = remote::get_user_key(&keys, int_key, fingerprint)?;

                // if user equals "new" then we need to create a new key
                helper = online::get_private_key_id(&ssh_key, &user)?;

                ssh_key
            } else {
                find::public_key(key)?
            };

            let key_type = find::key_type(&ssh_key.algorithm())?;

            let v = SshVault::new(&key_type, Some(ssh_key), None)?;

            let mut data = Vec::new();

            // isatty returns false if there's something in stdin.
            let input_stdin = !atty::is(atty::Stream::Stdin);

            // read from STDIN if there's something
            if input_stdin {
                std::io::stdin().read_to_end(&mut data)?;
            } else {
                let file = Builder::new()
                    .prefix(".vault-")
                    .suffix(".ssh")
                    .tempfile_in(tools::get_home()?)?;

                let editor = env::var("EDITOR").unwrap_or_else(|_| String::from("vi"));

                let status = Command::new(editor).arg(file.path()).status()?;

                if !status.success() {
                    return Err(anyhow::anyhow!("Editor exited with non-zero status code",));
                }

                data = fs::read(file.path())?;
                let _ = file_shred::shred_file(file.path());
            }

            // generate password (32 rand chars)
            let password: Secret<[u8; 32]> = crypto::gen_password()?;

            // create vault
            let out = v.create(password, &data)?;

            if let Some(vault) = vault {
                let path = PathBuf::from(vault);
                let mut file = fs::File::create(path)?;
                file.write_all(out.as_bytes())?;
            } else if helper.is_empty() {
                println!("{out}");
            } else {
                let line = "-".repeat(3);
                println!("Copy and paste this command to share the vault with others:\n\n{line}\n\necho \"{out}\" | ssh-vault view -k {helper}\n\n{line}\n");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
