use clap::{Arg, Command};

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
                .help("GitHub username or URL, optional [-k N] where N is the key index"),
        )
}
