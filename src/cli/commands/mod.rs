pub mod create;
pub mod edit;
pub mod fingerprint;
pub mod view;

use clap::{
    ColorChoice, Command,
    builder::styling::{AnsiColor, Effects, Styles},
};

use std::env;

pub fn new() -> Command {
    let styles = Styles::styled()
        .header(AnsiColor::Yellow.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Blue.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Green.on_default());

    Command::new("ssh-vault")
        .about("encrypt/decrypt using ssh keys")
        .arg_required_else_help(true)
        .version(env!("CARGO_PKG_VERSION"))
        .color(ColorChoice::Auto)
        .styles(styles)
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
        let command = new();

        assert_eq!(command.get_name(), "ssh-vault");
        assert_eq!(
            command.get_about().unwrap().to_string(),
            "encrypt/decrypt using ssh keys"
        );
        assert_eq!(
            command.get_version().unwrap().to_string(),
            env!("CARGO_PKG_VERSION")
        );
    }
}
