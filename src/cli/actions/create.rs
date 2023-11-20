use crate::cli::actions::{process_input, Action};
use crate::vault::{crypto, dio, find, online, remote, SshVault};
use anyhow::{anyhow, Result};
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
pub struct JsonVault {
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
            input,
        } => {
            // print the url from where to download the key
            let mut helper: Option<String> = None;

            let ssh_key: PublicKey = if let Some(user) = user {
                // if user equals "new" ignore the key and fingerprint
                if user == "new" && (key.is_some() || fingerprint.is_some()) {
                    return Err(anyhow!("Options -k and -f not required when using -u new"));
                }

                let int_key: Option<u32> = key.as_ref().and_then(|s| s.parse::<u32>().ok());

                // get keys from GitHub or remote server
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

            let mut buffer = Vec::new();

            // check if we need to skip the editor filename == "-"
            let skip_editor = input.as_ref().map_or(false, |stdin| stdin == "-");

            // setup Reader(input) and Writer (output)
            let (mut input, output) = dio::setup_io(input, vault)?;

            if !output.is_empty()? {
                return Err(anyhow!("Vault file already exists"));
            }

            if input.is_terminal() {
                if skip_editor {
                    input.read_to_end(&mut buffer)?;
                } else {
                    // use editor to handle input
                    process_input(&mut buffer, None)?;
                }
            } else {
                // read from stdin
                input.read_to_end(&mut buffer)?;
            }

            // generate password (32 rand chars)
            let password: Secret<[u8; 32]> = crypto::gen_password()?;

            // create vault
            let vault = v.create(password, &mut buffer)?;

            // return JSON or plain text, the helper is used to decrypt the vault
            format(output, vault, json, helper)?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn format<W: Write>(
    mut output: W,
    vault: String,
    json: bool,
    helper: Option<String>,
) -> Result<()> {
    // format the vault in json or plain text
    if json {
        let json_vault = JsonVault {
            vault,
            private_key: helper,
        };

        let json = serde_json::to_string(&json_vault)?;

        output.write_all(json.as_bytes())?;
    } else if let Some(helper) = helper {
        let format = format!("echo \"{vault}\" | ssh-vault view -k {helper}");
        output.write_all(format.as_bytes())?;
    } else {
        output.write_all(vault.as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format() {
        let mut output = Vec::new();
        let vault = "vault".to_string();
        let json = false;
        let helper = None;

        format(&mut output, vault, json, helper).unwrap();

        assert_eq!(output, b"vault");
    }

    #[test]
    fn test_format_helper() {
        let mut output = Vec::new();
        let vault = "vault".to_string();
        let json = false;
        let helper = Some("helper".to_string());

        format(&mut output, vault, json, helper).unwrap();

        assert_eq!(output, b"echo \"vault\" | ssh-vault view -k helper");
    }

    #[test]
    fn test_format_json() {
        let mut output = Vec::new();
        let vault = "vault".to_string();
        let json = true;
        let helper = None;

        format(&mut output, vault, json, helper).unwrap();

        assert_eq!(output, b"{\"vault\":\"vault\"}");
    }

    #[test]
    fn test_format_helper_json() {
        let mut output = Vec::new();
        let vault = "vault".to_string();
        let json = true;
        let helper = Some("helper".to_string());

        format(&mut output, vault, json, helper).unwrap();

        assert_eq!(output, b"{\"vault\":\"vault\",\"private_key\":\"helper\"}");
    }
}
