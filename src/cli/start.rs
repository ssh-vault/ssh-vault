use crate::cli::{actions::Action, commands, dispatcher};
use anyhow::Result;

/// Start the CLI
pub fn start() -> Result<Action> {
    let after_help = r#"
EXAMPLES:

Share a secret:

    echo "secret" | ssh-vault create -u new | pbcopy

Share a secret with a known user in GitHub:

    echo "secret" | ssh-vault create -u alice

Share a secret with Alice using its second key:

    echo "secret" | ssh-vault create -u alice -k 2

View a secret:

    ssh-vault view < secret.txt.vault

Edit a secret:

    ssh-vault edit secret.txt.vault

"#;
    let cmd = commands::new(after_help);
    let matches = cmd.get_matches();
    let action = dispatcher::dispatch(&matches)?;
    Ok(action)
}
