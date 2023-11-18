use crate::cli::{actions::Action, commands, dispatcher};
use anyhow::Result;

/// Start the CLI
pub fn start() -> Result<Action> {
    let cmd = commands::new();
    let matches = cmd.get_matches();
    let action = dispatcher::dispatch(&matches)?;
    Ok(action)
}
