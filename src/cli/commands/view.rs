use clap::{Arg, Command};

pub fn subcommand_view() -> Command {
    Command::new("view")
        .about("View an existing vault")
        .after_help(
            r"Examples:

View a secret:

    ssh-vault view < /path/to/secret.vault
",
        )
        .visible_alias("v")
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .help("Path to the private ssh key to use for decyrpting"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .help("Write output to file instead of stdout"),
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
                .help("file to read the vault from or reads from stdin if not specified"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    #[test]
    fn test_subcommand_view() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_view());

        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "view",
            "-k",
            "/path/to/id_rsa",
            "-p",
            "secret",
            "/path/to/vault",
        ])?;

        let m = matches
            .subcommand_matches("view")
            .ok_or("No view subcommand")?
            .to_owned();

        assert_eq!(
            m.get_one::<String>("key").ok_or("No key")?,
            "/path/to/id_rsa"
        );
        assert_eq!(
            m.get_one::<String>("vault").ok_or("No vault")?,
            "/path/to/vault"
        );
        assert_eq!(
            m.get_one::<String>("passphrase").ok_or("No passphrase")?,
            "secret"
        );
        Ok(())
    }

    #[test]
    fn test_subcommand_view_default() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_view());

        let matches = app.try_get_matches_from(vec!["ssh-vault", "view"])?;

        let m = matches
            .subcommand_matches("view")
            .ok_or("No view subcommand")?
            .to_owned();

        assert_eq!(m.get_one::<String>("key"), None);
        assert_eq!(m.get_one::<String>("vault"), None);
        assert_eq!(m.get_one::<String>("passphrase"), None);
        assert_eq!(m.get_one::<String>("output"), None);
        Ok(())
    }

    #[test]
    fn test_subcommand_view_short() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_view());

        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "v",
            "-k",
            "/path/to/id_rsa",
            "-p",
            "secret",
            "/path/to/vault",
        ])?;

        let m = matches
            .subcommand_matches("view")
            .ok_or("No view subcommand")?
            .to_owned();

        assert_eq!(
            m.get_one::<String>("key").ok_or("No key")?,
            "/path/to/id_rsa"
        );
        assert_eq!(
            m.get_one::<String>("vault").ok_or("No vault")?,
            "/path/to/vault"
        );
        assert_eq!(
            m.get_one::<String>("passphrase").ok_or("No passphrase")?,
            "secret"
        );
        assert_eq!(m.get_one::<String>("output"), None);
        Ok(())
    }

    #[test]
    fn test_subcommand_view_short_default() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_view());

        let matches = app.try_get_matches_from(vec!["ssh-vault", "v"])?;

        let m = matches
            .subcommand_matches("view")
            .ok_or("No view subcommand")?
            .to_owned();

        assert_eq!(m.get_one::<String>("key"), None);
        assert_eq!(m.get_one::<String>("vault"), None);
        assert_eq!(m.get_one::<String>("passphrase"), None);
        Ok(())
    }

    #[test]
    fn test_subcommand_view_output() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_view());

        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "view",
            "-k",
            "/path/to/id_rsa",
            "-p",
            "secret",
            "-o",
            "/path/to/output",
            "/path/to/vault",
        ])?;

        let m = matches
            .subcommand_matches("view")
            .ok_or("No view subcommand")?
            .to_owned();

        assert_eq!(
            m.get_one::<String>("key").ok_or("No key")?,
            "/path/to/id_rsa"
        );
        assert_eq!(
            m.get_one::<String>("vault").ok_or("No vault")?,
            "/path/to/vault"
        );
        assert_eq!(
            m.get_one::<String>("passphrase").ok_or("No passphrase")?,
            "secret"
        );
        assert_eq!(
            m.get_one::<String>("output").ok_or("No output")?,
            "/path/to/output"
        );
        Ok(())
    }
}
