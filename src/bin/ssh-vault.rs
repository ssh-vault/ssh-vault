use anyhow::Result;
use ssh_vault::cli::{actions, actions::Action, start};
use std::process;

// Main function
fn main() -> Result<()> {
    // Start the program
    let action = start()?;

    // Handle the action
    match action {
        Action::Fingerprint { .. } => {
            actions::fingerprint::handle(action)?;
        }
        Action::Create { .. } => {
            actions::create::handle(action)?;
        }
        Action::View { .. } => {
            actions::view::handle(action)?;
        }
        Action::Edit { .. } => {
            actions::edit::handle(action)?;
        }
        Action::Help => {
            eprintln!("No command or argument provided, try --help");

            // Exit the program with status code 1
            process::exit(1);
        }
    }

    Ok(())
}
