use clap::{Arg, Command, builder::ValueParser};

pub fn validator_user() -> ValueParser {
    ValueParser::from(move |s: &str| -> std::result::Result<String, String> {
        // Don't allow 'new' as a username
        if s == "new" {
            Err("Invalid user".to_owned())
        } else {
            Ok(s.to_owned())
        }
    })
}

pub fn subcommand_fingerprint() -> Command {
    Command::new("fingerprint")
        .about("Print the fingerprint of a public ssh key")
        .visible_alias("f")
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .help("Path to public ssh key or index when using option -u"),
        )
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .help("GitHub username or URL, optional [-k N] where N is the key index")
                .value_parser(validator_user()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_user() {
        let app = Command::new("ssh-vault").subcommand(subcommand_fingerprint());
        let matches = app.try_get_matches_from(vec!["ssh-vault", "fingerprint", "-u", "new"]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_validator_user_ok() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_fingerprint());
        let matches = app.try_get_matches_from(vec!["ssh-vault", "fingerprint", "-u", "test"])?;

        let m = matches
            .subcommand_matches("fingerprint")
            .ok_or("No fingerprint subcommand")?
            .to_owned();
        assert_eq!(m.get_one::<String>("user").ok_or("No user")?, "test");
        assert!(m.get_one::<String>("key").is_none());
        Ok(())
    }

    #[test]
    fn test_validator_user_with_key() -> Result<(), Box<dyn std::error::Error>> {
        let app = Command::new("ssh-vault").subcommand(subcommand_fingerprint());
        let matches =
            app.try_get_matches_from(vec!["ssh-vault", "fingerprint", "-u", "test", "-k", "3"])?;

        let m = matches
            .subcommand_matches("fingerprint")
            .ok_or("No fingerprint subcommand")?
            .to_owned();
        assert_eq!(m.get_one::<String>("user").ok_or("No user")?, "test");
        assert_eq!(m.get_one::<String>("key").ok_or("No key")?, "3");
        Ok(())
    }
}
