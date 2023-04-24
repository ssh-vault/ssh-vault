use anyhow::Result;
use ssh_vault::cli::{actions, actions::Action, start};

fn main() -> Result<()> {
    let action = start()?;

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
            std::process::exit(1);
        }
    }

    Ok(())
}
