use clap::{Arg, Command};

pub fn subcommand_edit() -> Command {
    Command::new("edit")
        .about("Edit an existing vault")
        .after_help(
            r"Examples:

Edit a secret:

    ssh-vault edit /path/to/secret.vault
",
        )
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
    fn test_subcommand_edit_ok() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_edit());
        let matches =
            app.try_get_matches_from(vec!["ssh-vault", "edit", "-k", "test", "/tmp/vault"])?;

        let m = matches
            .subcommand_matches("edit")
            .ok_or("No edit subcommand")?
            .to_owned();
        assert_eq!(m.get_one::<String>("key").ok_or("No key")?, "test");
        assert!(m.get_one::<String>("passphrase").is_none());
        assert_eq!(
            m.get_one::<String>("vault").ok_or("No vault")?,
            "/tmp/vault"
        );
        Ok(())
    }

    #[test]
    fn test_subcommand_edit_with_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_edit());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "edit",
            "-k",
            "test",
            "-p",
            "passphrase",
            "/tmp/vault",
        ])?;

        let m = matches
            .subcommand_matches("edit")
            .ok_or("No edit subcommand")?
            .to_owned();
        assert_eq!(m.get_one::<String>("key").ok_or("No key")?, "test");
        assert_eq!(
            m.get_one::<String>("passphrase").ok_or("No passphrase")?,
            "passphrase"
        );
        assert_eq!(
            m.get_one::<String>("vault").ok_or("No vault")?,
            "/tmp/vault"
        );
        Ok(())
    }
}
