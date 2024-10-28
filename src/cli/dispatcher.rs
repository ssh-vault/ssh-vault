use crate::cli::actions::Action;

use anyhow::{Context, Result};
use secrecy::SecretString;

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
                fingerprint: sub_m.get_one("fingerprint").map(|s: &String| s.to_string()),
                input: sub_m.get_one("input").map(|s: &String| s.to_string()),
                json: sub_m.get_one("json").copied().unwrap_or(false),
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                user: sub_m.get_one("user").map(|s: &String| s.to_string()),
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
                    .map(|s: &String| SecretString::from(s.clone())),
            })
        }
        Some("edit") => {
            let sub_m = sub_m("edit")?;
            Ok(Action::Edit {
                key: sub_m.get_one("key").map(|s: &String| s.to_string()),
                passphrase: sub_m
                    .get_one("passphrase")
                    .map(|s: &String| SecretString::from(s.clone())),
                vault: sub_m
                    .get_one("vault")
                    .map(|s: &String| s.to_string())
                    .ok_or_else(|| anyhow::anyhow!("Vault path required"))?,
            })
        }
        _ => Ok(Action::Help),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        actions::Action,
        commands::{create, edit, fingerprint, view},
    };
    use clap::Command;
    use secrecy::ExposeSecret;

    #[test]
    fn test_dispatch_fingerprint_default() {
        let cmd = Command::new("test").subcommand(fingerprint::subcommand_fingerprint());
        let matches = cmd.try_get_matches_from(vec!["test", "fingerprint"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Fingerprint { key, user } => {
                assert_eq!(key, None);
                assert_eq!(user, None);
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_fingerprint_with_key() {
        let cmd = Command::new("test").subcommand(fingerprint::subcommand_fingerprint());
        let matches =
            cmd.try_get_matches_from(vec!["test", "fingerprint", "--key", "test_data/id_rsa.pub"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Fingerprint { key, user } => {
                assert_eq!(key, Some("test_data/id_rsa.pub".to_string()));
                assert_eq!(user, None);
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_fingerprint_with_user() {
        let cmd = Command::new("test").subcommand(fingerprint::subcommand_fingerprint());
        let matches = cmd.try_get_matches_from(vec!["test", "fingerprint", "--user", "test"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Fingerprint { key, user } => {
                assert_eq!(key, None);
                assert_eq!(user, Some("test".to_string()));
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_fingerprint_with_key_and_user() {
        let cmd = Command::new("test").subcommand(fingerprint::subcommand_fingerprint());
        let matches = cmd.try_get_matches_from(vec![
            "test",
            "fingerprint",
            "--key",
            "test_data/id_rsa.pub",
            "--user",
            "test",
        ]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Fingerprint { key, user } => {
                assert_eq!(key, Some("test_data/id_rsa.pub".to_string()));
                assert_eq!(user, Some("test".to_string()));
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_create_default() {
        let cmd = Command::new("test").subcommand(create::subcommand_create());
        let matches = cmd.try_get_matches_from(vec!["test", "create"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Create {
                fingerprint,
                input,
                json,
                key,
                user,
                vault,
            } => {
                assert_eq!(fingerprint, None);
                assert_eq!(input, None);
                assert_eq!(json, false);
                assert_eq!(key, None);
                assert_eq!(user, None);
                assert_eq!(vault, None);
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_create_with_json() {
        let cmd = Command::new("test").subcommand(create::subcommand_create());
        let matches = cmd.try_get_matches_from(vec!["test", "create", "--json"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Create {
                fingerprint,
                input,
                json,
                key,
                user,
                vault,
            } => {
                assert_eq!(fingerprint, None);
                assert_eq!(input, None);
                assert_eq!(json, true);
                assert_eq!(key, None);
                assert_eq!(user, None);
                assert_eq!(vault, None);
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_edit() {
        let cmd = Command::new("test").subcommand(edit::subcommand_edit());
        let matches =
            cmd.try_get_matches_from(vec!["test", "edit", "-p", "secret", "test_data/id_rsa"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Edit {
                key,
                passphrase,
                vault,
            } => {
                assert_eq!(key, None);
                assert_eq!("secret", passphrase.unwrap().expose_secret());
                assert_eq!(vault, String::from("test_data/id_rsa"));
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_edit_no_vault() {
        let cmd = Command::new("test").subcommand(edit::subcommand_edit());
        let matches = cmd.try_get_matches_from(vec!["test", "edit"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_dispatch_view() {
        let cmd = Command::new("test").subcommand(view::subcommand_view());
        let matches = cmd.try_get_matches_from(vec!["test", "view", "-p", "secret"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::View {
                key,
                vault,
                output,
                passphrase,
            } => {
                assert_eq!(key, None);
                assert_eq!(vault, None);
                assert_eq!(output, None);
                assert_eq!("secret", passphrase.unwrap().expose_secret());
            }
            _ => panic!("Wrong action"),
        }
    }

    #[test]
    fn test_dispatch_no_match() {
        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(vec!["test"]);
        assert!(matches.is_ok());
        let matches = matches.unwrap();
        let action = dispatch(&matches).unwrap();
        match action {
            Action::Help => {}
            _ => panic!("Wrong action"),
        }
    }
}
