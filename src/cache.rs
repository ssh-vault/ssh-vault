use crate::tools::get_home;
use anyhow::{Result, anyhow};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

// Load the response from a cache file ~/.ssh/vault/keys/<key>
/// # Errors
/// Return an error if the cache is older than 30 days
pub fn get(key: &str) -> Result<String> {
    let cache = get_cache_path(key)?;
    if cache.exists() {
        let metadata = fs::metadata(&cache);
        let last_modified = metadata.map_or_else(
            |_| SystemTime::now(),
            |meta| meta.modified().unwrap_or_else(|_| SystemTime::now()),
        );

        // Calculate the duration since the file was last modified
        let duration_since_modified = SystemTime::now()
            .duration_since(last_modified)
            .unwrap_or(Duration::from_secs(0));

        // Return an error if the cache is older than 30 days
        if duration_since_modified > Duration::from_secs(30 * 24 * 60 * 60) {
            Err(anyhow!("cache expired"))
        } else {
            Ok(fs::read_to_string(cache)?)
        }
    } else {
        Err(anyhow!("cache not found"))
    }
}

/// Save the response to a cache file ~/.ssh/vault/keys/<key>
/// # Errors
/// Return an error if the cache file can't be created
pub fn put(key: &str, response: &str) -> Result<()> {
    let cache = get_cache_path(key)?;
    // Create parent directories if they don't exist
    if let Some(parent_dir) = std::path::Path::new(&cache).parent() {
        fs::create_dir_all(parent_dir)?;
    }
    Ok(fs::write(cache, response)?)
}

/// Get the path to the cache file ~/.ssh/vault/keys/<key>
/// # Errors
/// Return an error if we can't get the path to the cache file
fn get_cache_path(key: &str) -> Result<PathBuf> {
    let ssh_vault = get_ssh_vault_path()?;
    Ok(ssh_vault.join("keys").join(key))
}

/// Get the path to the ssh-vault directory ~/.ssh/vault
/// # Errors
/// Return an error if we can't get the path to the ssh-vault directory
fn get_ssh_vault_path() -> Result<PathBuf> {
    let home = get_home()?;
    Ok(Path::new(&home).join(".ssh").join("vault"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_get_cache_path() {
        let cache = get_cache_path("test").unwrap();
        assert_eq!(cache.is_dir(), false);
        assert_eq!(
            cache.to_str(),
            get_home()
                .unwrap()
                .join(".ssh")
                .join("vault")
                .join("keys")
                .join("test")
                .to_str()
        );
    }

    #[test]
    fn test_get_ssh_vault_path() {
        let ssh_vault = get_ssh_vault_path().unwrap();
        assert_eq!(ssh_vault.is_file(), false);
        assert_eq!(
            ssh_vault.to_str(),
            get_home().unwrap().join(".ssh").join("vault").to_str()
        );
    }

    #[test]
    fn test_put() {
        let cache = get_cache_path("test-2").unwrap();
        put("test-2", "test").unwrap();

        assert_eq!(cache.is_file(), true);
        assert_eq!(cache.is_dir(), false);
        assert_eq!(cache.exists(), true);
        assert_eq!(
            cache.to_str(),
            get_home()
                .unwrap()
                .join(".ssh")
                .join("vault")
                .join("keys")
                .join("test-2")
                .to_str()
        );
        fs::remove_file(cache).unwrap();
    }

    #[test]
    fn test_get() {
        let cache = get_cache_path("test-3").unwrap();
        put("test-3", "test").unwrap();
        let response = get("test-3").unwrap();
        assert_eq!(response, "test");
        fs::remove_file(cache).unwrap();
    }
}
