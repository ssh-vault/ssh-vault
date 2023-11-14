use clap::{builder::ValueParser, Arg, Command};

pub fn validator_user() -> ValueParser {
    ValueParser::from(move |s: &str| -> std::result::Result<String, String> {
        // Don't allow 'new' as a username
        if s != "new" {
            Ok(s.to_owned())
        } else {
            Err("Invalid user".to_owned())
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
