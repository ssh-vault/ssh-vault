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
use tempfile::{Builder, NamedTempFile};

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

    read_and_scrub(&mut tmpfile, buf)
}

/// Read the temporary file's contents into `buf`, then overwrite the file's
/// bytes with zeros.
///
/// The scrub is a best-effort measure before the `NamedTempFile` is unlinked on
/// drop: in-place overwrite is not guaranteed on CoW/journaling/SSD
/// filesystems, so the unlink is the real guarantee. The rewind before writing
/// is essential — `read_to_end` leaves the cursor at EOF, so writing without
/// seeking back would *append* the zeros after the plaintext (doubling the
/// file) and leave the secret fully intact.
///
/// # Errors
///
/// Returns an error if any seek/read/write/truncate/sync operation fails.
fn read_and_scrub(tmpfile: &mut NamedTempFile, buf: &mut Vec<u8>) -> Result<usize> {
    // Rewind and read the edited content.
    tmpfile.seek(SeekFrom::Start(0))?;
    tmpfile.read_to_end(buf)?;

    // Rewind again before overwriting, then truncate to the original length and
    // flush so the zeros reach disk.
    tmpfile.seek(SeekFrom::Start(0))?;
    let zeros = vec![0u8; buf.len()];
    tmpfile.write_all(&zeros)?;
    tmpfile.as_file().set_len(u64::try_from(buf.len())?)?;
    tmpfile.as_file().sync_all()?;

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

    // Regression test for the temp-file scrub in `read_and_scrub`.
    //
    // The original bug: after `read_to_end` the cursor sits at EOF, so writing
    // the zero buffer *appended* it (doubling the file) instead of overwriting
    // the plaintext, leaving the secret fully intact on disk. This asserts the
    // file is left fully zeroed and at its original length, not doubled.
    #[test]
    fn test_read_and_scrub_overwrites_plaintext() {
        use super::read_and_scrub;
        use std::io::{Seek, SeekFrom, Write};

        let secret = b"top secret plaintext";
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(secret).unwrap();
        tmpfile.seek(SeekFrom::Start(0)).unwrap();

        let mut buf = Vec::new();
        let n = read_and_scrub(&mut tmpfile, &mut buf).unwrap();

        // The edited content is read back correctly.
        assert_eq!(n, secret.len());
        assert_eq!(buf.as_slice(), secret);

        // The on-disk file is exactly `secret.len()` bytes (not doubled) and
        // contains no plaintext — every byte is zero.
        let on_disk = std::fs::read(tmpfile.path()).unwrap();
        assert_eq!(on_disk.len(), secret.len());
        assert!(on_disk.iter().all(|&b| b == 0));
        assert!(!on_disk.windows(secret.len()).any(|w| w == secret));
    }

    // Regression test: `view -o <file>` must not leave stale trailing bytes when
    // the destination file already exists and is longer than the new plaintext.
    #[test]
    fn test_view_output_truncates_stale_bytes() {
        let secret = "short";

        let mut input = NamedTempFile::new().unwrap();
        input.write_all(secret.as_bytes()).unwrap();
        let vault_file = NamedTempFile::new().unwrap();

        let create = Action::Create {
            fingerprint: None,
            key: Some("test_data/ed25519.pub".to_string()),
            user: None,
            vault: Some(vault_file.path().to_str().unwrap().to_string()),
            json: false,
            input: Some(input.path().to_str().unwrap().to_string()),
        };
        assert!(create::handle(create).is_ok());

        // Pre-populate the output file with content longer than the secret.
        let mut output_file = NamedTempFile::new().unwrap();
        output_file
            .write_all(b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            .unwrap();

        let view = Action::View {
            key: Some("test_data/ed25519".to_string()),
            output: Some(output_file.path().to_str().unwrap().to_string()),
            passphrase: None,
            vault: Some(vault_file.path().to_str().unwrap().to_string()),
        };
        assert!(view::handle(view).is_ok());

        // The file must contain exactly the secret — no leftover 'X' bytes.
        let contents = std::fs::read_to_string(output_file.path()).unwrap();
        assert_eq!(contents, secret);
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
