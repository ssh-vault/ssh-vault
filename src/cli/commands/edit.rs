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
