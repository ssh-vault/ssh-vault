use crate::cli::actions::Action;

use anyhow::{Context, Result};
use secrecy::Secret;

pub fn dispatch(matches: &clap::ArgMatches) -> Result<Action> {
    // Closure to return subcommand matches
    let sub_m = |subcommand| -> Result<&clap::ArgMatches> {
        matches
            .subcommand_matches(subcommand)
            .context("arguments not found")
    };

    match matches.subcommand_name() {
        Some("fingerprint") => {
            let sub_m = sub_m("fingerprint")?;
            Ok(Action::Fingerprint {
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                user: sub_m.get_one("user").map(|s: &String| s.to_string()),
            })
        }
        Some("create") => {
            let sub_m = sub_m("create")?;
            Ok(Action::Create {
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                user: sub_m.get_one("user").map(|s: &String| s.to_string()),
                fingerprint: sub_m.get_one("fingerprint").map(|s: &String| s.to_string()),
                vault: sub_m.get_one("vault").map(|s: &String| s.to_string()),
            })
        }
        Some("view") => {
            let sub_m = sub_m("view")?;
            Ok(Action::View {
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                vault: sub_m.get_one("vault").map(|s: &String| s.to_string()),
                output: sub_m.get_one("output").map(|s: &String| s.to_string()),
                passphrase: sub_m
                    .get_one("passphrase")
                    .map(|s: &String| Secret::new(s.to_string())),
            })
        }
        Some("edit") => {
            let sub_m = sub_m("edit")?;
            Ok(Action::Edit {
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                passphrase: sub_m
                    .get_one("passphrase")
                    .map(|s: &String| Secret::new(s.to_string())),
                vault: sub_m
                    .get_one("vault")
                    .map(|s: &String| s.to_string())
                    .ok_or_else(|| anyhow::anyhow!("Vault path required"))?,
            })
        }
        _ => Ok(Action::Help),
    }
}
