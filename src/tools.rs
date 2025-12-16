use anyhow::{Result, anyhow};
use std::path::PathBuf;

/// Return the user's home directory.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined.
pub fn get_home() -> Result<PathBuf> {
    home::home_dir().map_or_else(|| Err(anyhow!("Could not find home directory")), Ok)
}

/// Filter fetched text to only include supported SSH public keys.
///
/// # Errors
///
/// Returns an error if no supported keys are found.
pub fn filter_fetched_keys(response: &str) -> Result<String> {
    let mut filtered_keys = String::new();

    for line in response.lines() {
        if line.starts_with("ssh-rsa") || line.starts_with("ssh-ed25519") {
            filtered_keys.push_str(line);
            filtered_keys.push('\n'); // Add a newline to separate the lines
        }
    }

    if filtered_keys.is_empty() {
        Err(anyhow!("No SSH keys (ssh-rsa or ssh-ed25519) found"))
    } else {
        Ok(filtered_keys)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_get_home() -> Result<(), Box<dyn std::error::Error>> {
        let home = get_home()?;
        assert!(home.is_dir());
        Ok(())
    }
}
