use clap::{Arg, Command};

pub fn subcommand_edit() -> Command {
    Command::new("edit")
        .about("Edit an existing vault")
        .visible_alias("e")
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .help("Path to the private ssh key to use for decyrpting"),
        )
        .arg(
            Arg::new("passphrase")
                .short('p')
                .long("passphrase")
                .env("SSH_VAULT_PASSPHRASE")
                .help("Passphrase of the private ssh key"),
        )
        .arg(
            Arg::new("vault")
                .required(true)
                .help("Path of the vault to edit"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subcommand_edit() {
        let app = Command::new("ssh-vault").subcommand(subcommand_edit());
        let matches = app.try_get_matches_from(vec!["ssh-vault", "edit", "-k", "test"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_subcommand_edit_ok() {
        let app = Command::new("ssh-vault").subcommand(subcommand_edit());
        let matches =
            app.try_get_matches_from(vec!["ssh-vault", "edit", "-k", "test", "/tmp/vault"]);
        assert!(matches.is_ok());

        let m = matches
            .unwrap()
            .subcommand_matches("edit")
            .unwrap()
            .to_owned();
        assert_eq!(m.get_one::<String>("key").unwrap(), "test");
        assert_eq!(m.get_one::<String>("passphrase").is_none(), true);
        assert_eq!(m.get_one::<String>("vault").unwrap(), "/tmp/vault");
    }

    #[test]
    fn test_subcommand_edit_with_passphrase() {
        let app = Command::new("ssh-vault").subcommand(subcommand_edit());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "edit",
            "-k",
            "test",
            "-p",
            "passphrase",
            "/tmp/vault",
        ]);
        assert!(matches.is_ok());

        let m = matches
            .unwrap()
            .subcommand_matches("edit")
            .unwrap()
            .to_owned();
        assert_eq!(m.get_one::<String>("key").unwrap(), "test");
        assert_eq!(m.get_one::<String>("passphrase").unwrap(), "passphrase");
        assert_eq!(m.get_one::<String>("vault").unwrap(), "/tmp/vault");
    }
}
