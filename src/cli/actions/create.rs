use crate::cli::actions::Action;
use crate::{
    tools,
    vault::{crypto, find, online, remote, SshVault},
};
use anyhow::{anyhow, Result};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use std::{
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::Command,
};
use tempfile::Builder;

#[derive(Serialize, Deserialize)]
struct JsonVault {
    vault: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

/// Handle the create action
pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Create {
            fingerprint,
            key,
            user,
            vault,
            json,
        } => {
            // print the url from where to download the key
            let mut helper: Option<String> = None;

            let ssh_key: PublicKey = if let Some(user) = user {
                // if user equals "new" ignore the key and fingerprint
                if user == "new" && (key.is_some() || fingerprint.is_some()) {
                    return Err(anyhow!("Options -k and -f not required when using -u new"));
                }

                let int_key: Option<u32> = key.as_ref().and_then(|s| s.parse::<u32>().ok());

                // get keys fro GitHub or remote server
                let keys = remote::get_keys(&user)?;

                // search key using -k or -f options
                let ssh_key = remote::get_user_key(&keys, int_key, fingerprint)?;

                // if user equals "new" then we need to create a new key
                if let Ok(key) = online::get_private_key_id(&ssh_key, &user) {
                    if !key.is_empty() {
                        helper = Some(key);
                    }
                }

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

            print_or_safe(out, vault, json, helper)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Print or safe the vault
fn print_or_safe(
    vault: String,
    path: Option<String>,
    json: bool,
    helper: Option<String>,
) -> Result<()> {
    let format = if json {
        return_json(vault, helper)?
    } else if let Some(helper) = helper {
        format!("echo \"{vault}\" | ssh-vault view -k {helper}")
    } else {
        vault
    };

    if let Some(path) = path {
        let vault_path = PathBuf::from(path);
        let mut file = fs::File::create(vault_path)?;
        file.write_all(format.as_bytes())?;
    } else {
        println!("{format}");
    }
    Ok(())
}

fn return_json(vault: String, private_key: Option<String>) -> Result<String> {
    let json = JsonVault { vault, private_key };
    Ok(serde_json::to_string(&json)?)
}
