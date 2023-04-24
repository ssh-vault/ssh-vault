use crate::cli::{actions::Action, commands, dispatcher};
use anyhow::Result;

/// Start the CLI
pub fn start() -> Result<Action> {
    let after_help = format!("EXAMPLES: {}", 1);
    let cmd = commands::new(&after_help);
    let matches = cmd.get_matches();
    let action = dispatcher::dispatch(&matches)?;
    Ok(action)
}
