pub mod create;
pub mod edit;
pub mod fingerprint;
pub mod view;

use clap::Command;
use std::env;

pub fn new(after_help: &str) -> Command {
    let after_help_string = after_help.to_string();

    Command::new("ssh-vault")
        .about("encrypt/decrypt using ssh keys")
        .version(env!("CARGO_PKG_VERSION"))
        .after_help(after_help_string)
        .subcommand(create::subcommand_create())
        .subcommand(edit::subcommand_edit())
        .subcommand(fingerprint::subcommand_fingerprint())
        .subcommand(view::subcommand_view())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let after_help = "after help";
        let command = new(after_help);

        assert_eq!(command.get_name(), "ssh-vault");
        assert_eq!(
            command.get_about().unwrap().to_string(),
            "encrypt/decrypt using ssh keys"
        );
        assert_eq!(
            command.get_version().unwrap().to_string(),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(command.get_after_help().unwrap().to_string(), after_help);
    }
}
