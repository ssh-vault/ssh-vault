pub mod create;
pub mod edit;
pub mod fingerprint;
pub mod view;

use crate::tools;
use anyhow::{Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use std::{
    env,
    io::{Read, Seek, SeekFrom, Write},
    process::Command,
};
use tempfile::Builder;

#[derive(Debug)]
pub enum Action {
    Fingerprint {
        key: Option<String>,
        user: Option<String>,
    },
    Create {
        fingerprint: Option<String>,
        input: Option<String>,
        json: bool,
        key: Option<String>,
        user: Option<String>,
        vault: Option<String>,
    },
    View {
        key: Option<String>,
        output: Option<String>,
        passphrase: Option<SecretString>,
        vault: Option<String>,
    },
    Edit {
        key: Option<String>,
        passphrase: Option<SecretString>,
        vault: String,
    },
    Help,
}

/// Opens an editor and returns the edited content.
///
/// # Errors
///
/// Returns an error if the temporary file cannot be created, if the editor
/// command is empty or fails, or if reading/writing the temporary file fails.
pub fn process_input(buf: &mut Vec<u8>, data: Option<SecretString>) -> Result<usize> {
    let mut tmpfile = Builder::new()
        .prefix(".vault-")
        .suffix(".ssh")
        .tempfile_in(tools::get_home()?)?;

    if let Some(data) = data {
        write!(tmpfile, "{}", data.expose_secret())?;
    }

    let editor = env::var("EDITOR").unwrap_or_else(|_| String::from("vi"));

    let editor_parts = shell_words::split(&editor)?;
    let command = editor_parts
        .first()
        .ok_or_else(|| anyhow!("EDITOR command is empty"))?;

    let status = Command::new(command)
        .args(editor_parts.get(1..).unwrap_or(&[]))
        .arg(tmpfile.path())
        .status()?;

    if !status.success() {
        return Err(anyhow!("Editor exited with non-zero status code"));
    }

    // Seek to start
    tmpfile.seek(SeekFrom::Start(0))?;

    // read the file
    tmpfile.read_to_end(buf)?;

    // Fill the file with zeros
    let zeros = vec![0u8; buf.len()];
    tmpfile.write_all(&zeros)?;

    Ok(buf.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::cli::actions::{Action, create, edit, fingerprint, view};
    use serde_json::Value;
    use std::io::Write;
    use tempfile::NamedTempFile;

    struct Test {
        input: &'static str,
        public_key: &'static str,
        private_key: &'static str,
        header: &'static str,
    }

    #[test]
    fn test_create_view_edit_with_input() {
        let tests = [
            Test {
                input: "Machs na",
                public_key: "test_data/ed25519.pub",
                private_key: "test_data/ed25519",
                header: "SSH-VAULT;CHACHA20-POLY1305",
            },
            Test {
                input: "Machs na",
                public_key: "test_data/id_rsa.pub",
                private_key: "test_data/id_rsa",
                header: "SSH-VAULT;AES256",
            },
            Test {
                input: "Arrachera is a Mexican dish made from marinated and grilled skirt steak. The steak is seasoned with a mixture of spices and marinades, giving it a rich and savory flavor. Commonly served in tacos or fajitas, arrachera is known for its tenderness and versatility in Mexican cuisine",
                public_key: "test_data/ed25519.pub",
                private_key: "test_data/ed25519",
                header: "SSH-VAULT;CHACHA20-POLY1305",
            },
        ];

        for test in &tests {
            let input = test.input;
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(input.as_bytes()).unwrap();
            let vault_file = NamedTempFile::new().unwrap();

            let create = Action::Create {
                fingerprint: None,
                key: Some(test.public_key.to_string()),
                user: None,
                vault: Some(vault_file.path().to_str().unwrap().to_string()),
                json: false,
                input: Some(temp_file.path().to_str().unwrap().to_string()),
            };
            let vault = create::handle(create);
            assert!(vault.is_ok());

            let vault_contents = std::fs::read_to_string(&vault_file).unwrap();
            assert!(vault_contents.starts_with(test.header));

            let output = NamedTempFile::new().unwrap();
            let view = Action::View {
                key: Some(test.private_key.to_string()),
                output: Some(output.path().to_str().unwrap().to_string()),
                passphrase: None,
                vault: Some(vault_file.path().to_str().unwrap().to_string()),
            };
            let vault_view = view::handle(view);
            assert!(vault_view.is_ok());

            let output = std::fs::read_to_string(output).unwrap();
            assert_eq!(input, output);

            let edit = Action::Edit {
                key: Some(test.private_key.to_string()),
                passphrase: None,
                vault: vault_file.path().to_str().unwrap().to_string(),
            };

            // set EDITOR to cat instead of vi
            temp_env::with_vars([("EDITOR", Some("cat"))], || {
                let vault_edit = edit::handle(edit);
                assert!(vault_edit.is_ok());
            });

            let vault_contents_after_edit = std::fs::read_to_string(&vault_file).unwrap();
            assert_ne!(vault_contents, vault_contents_after_edit);

            // check if we can still view the vault
            let output = NamedTempFile::new().unwrap();
            let view = Action::View {
                key: Some(test.private_key.to_string()),
                output: Some(output.path().to_str().unwrap().to_string()),
                passphrase: None,
                vault: Some(vault_file.path().to_str().unwrap().to_string()),
            };
            let vault_view = view::handle(view);
            assert!(vault_view.is_ok());

            let output = std::fs::read_to_string(output).unwrap();
            assert_eq!(input, output);

            // try to create again with the same vault (should fail)
            let create = Action::Create {
                fingerprint: None,
                key: Some(test.public_key.to_string()),
                user: None,
                vault: Some(vault_file.path().to_str().unwrap().to_string()),
                json: false,
                input: Some(temp_file.path().to_str().unwrap().to_string()),
            };
            let vault = create::handle(create);
            assert!(vault.is_err());
        }
    }

    #[test]
    fn test_create_with_json() -> Result<(), Box<dyn std::error::Error>> {
        let tests = [
            Test {
                input: "Three may keep a secret, if two of them are dead",
                public_key: "test_data/ed25519.pub",
                private_key: "test_data/ed25519",
                header: "SSH-VAULT;CHACHA20-POLY1305",
            },
            Test {
                input: "Hello World!",
                public_key: "test_data/ed25519.pub",
                private_key: "test_data/ed25519",
                header: "SSH-VAULT;CHACHA20-POLY1305",
            },
        ];

        for test in &tests {
            let input = test.input;
            let mut temp_file = NamedTempFile::new().unwrap();
            temp_file.write_all(input.as_bytes()).unwrap();
            let vault_json = NamedTempFile::new().unwrap();

            let create = Action::Create {
                fingerprint: None,
                key: Some(test.public_key.to_string()),
                user: None,
                vault: Some(vault_json.path().to_str().unwrap().to_string()),
                json: true,
                input: Some(temp_file.path().to_str().unwrap().to_string()),
            };
            let vault = create::handle(create);
            assert!(vault.is_ok());

            let vault_contents = std::fs::read_to_string(&vault_json).unwrap();
            let json: Value = serde_json::from_str(&vault_contents).unwrap();
            let vault_str = json
                .get("vault")
                .and_then(|v| v.as_str())
                .ok_or("Failed to get vault from JSON")?;

            let mut vault_file = NamedTempFile::new().unwrap();
            vault_file.write_all(vault_str.as_bytes()).unwrap();
            let output = NamedTempFile::new().unwrap();

            let view = Action::View {
                key: Some(test.private_key.to_string()),
                output: Some(output.path().to_str().unwrap().to_string()),
                passphrase: None,
                vault: Some(vault_file.path().to_str().unwrap().to_string()),
            };
            let vault_view = view::handle(view);
            assert!(vault_view.is_ok());

            let output = std::fs::read_to_string(output).unwrap();
            assert_eq!(input, output);
        }
        Ok(())
    }

    #[test]
    fn test_fingerprint() {
        let fingerprint = Action::Fingerprint {
            key: Some("test_data/ed25519.pub".to_string()),
            user: None,
        };

        let fingerprint = fingerprint::handle(fingerprint);
        assert!(fingerprint.is_ok());
    }
}
