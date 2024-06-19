use crate::cli::actions::Action;
use crate::vault::{fingerprint, remote};
use anyhow::Result;

/// Handle the fingerprint action.
pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Fingerprint { key, user } => match (key, user) {
            (Some(key), None) => {
                let fingerprint = fingerprint::fingerprint(&key)?;
                println!("{fingerprint}");
            }
            (None, Some(user)) => {
                let keys = remote::get_keys(&user)?;
                let fingerprints = fingerprint::get_remote_fingerprints(&keys, None)?;

                let max_key_length = fingerprints
                    .iter()
                    .map(|f| f.key.len())
                    .max()
                    .unwrap_or_default();

                for fingerprint in &fingerprints {
                    println!("{fingerprint:max_key_length$}");
                }
            }
            (Some(key), Some(user)) => {
                let key_number: Result<u32, _> = key.parse();
                let keys = remote::get_keys(&user)?;

                match key_number {
                    Ok(key) => {
                        let fingerprints = fingerprint::get_remote_fingerprints(&keys, Some(key))?;

                        let max_key_length = fingerprints
                            .iter()
                            .map(|f| f.key.len())
                            .max()
                            .unwrap_or_default();

                        for fingerprint in &fingerprints {
                            println!("{fingerprint:max_key_length$}");
                        }
                    }
                    Err(_) => {
                        eprintln!("When using -u, [-k N] must be a numeric key index.");
                    }
                }
            }
            (None, None) => {
                let fingerprints = fingerprint::fingerprints()?;

                let max_key_length = fingerprints
                    .iter()
                    .map(|f| f.key.len())
                    .max()
                    .unwrap_or_default();

                for fingerprint in &fingerprints {
                    println!("{fingerprint:max_key_length$}");
                }
            }
        },
        _ => unreachable!(),
    }
    Ok(())
}
