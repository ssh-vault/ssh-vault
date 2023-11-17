use anyhow::{anyhow, Result};
use std::path::PathBuf;

pub fn get_home() -> Result<PathBuf> {
    home::home_dir().map_or_else(|| Err(anyhow!("Could not find home directory")), Ok)
}

pub fn get_config() -> Result<()> {
    let home = get_home()?;
    let config = home.join(".config").join("ssh-vault");

    if !config.is_dir() {
        std::fs::create_dir_all(&config)?;
    }

    Ok(())
}

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
mod tests {
    use super::*;

    #[test]
    fn test_get_home() {
        let home = get_home().unwrap();
        assert_eq!(home.is_dir(), true);
    }
}
