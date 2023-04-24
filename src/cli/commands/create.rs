use clap::{Arg, Command};

pub fn subcommand_create() -> Command {
    Command::new("create")
        .about("Create a new vault")
        .visible_alias("c")
        .arg(
            Arg::new("fingerprint")
                .short('f')
                .long("fingerprint")
                .help("Create a vault using the key matching the specified fingerprint"),
        )
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
        .arg(Arg::new("vault").help("file to store the vault or writes to stdout if not specified"))
}
