use crate::tools::get_home;
use anyhow::{Result, anyhow};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

// Load the response from a cache file ~/.ssh/vault/keys/`<key>`
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
        if duration_since_modified > Duration::from_hours(30 * 24) {
            Err(anyhow!("cache expired"))
        } else {
            Ok(fs::read_to_string(cache)?)
        }
    } else {
        Err(anyhow!("cache not found"))
    }
}

/// Save the response to a cache file ~/.ssh/vault/keys/`<key>`
/// # Errors
/// Return an error if the cache file can't be created
pub fn put(key: &str, response: &str) -> Result<()> {
    let cache = get_cache_path(key)?;

    // Create parent directories if they don't exist. The cache path is
    // predictable (md5 of the URL), so on a shared host a lax-permission
    // directory would let another user read or overwrite cached keys (cache
    // poisoning) — and `find` may even cache a fetched private key here.
    // Restrict to the owner.
    if let Some(parent_dir) = cache.parent() {
        fs::create_dir_all(parent_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Enforce 0700 on ssh-vault's own cache dirs even if they already
            // existed with looser permissions. Only these two — never ~/.ssh.
            let vault_dir = get_ssh_vault_path()?;
            for dir in [vault_dir.join("keys"), vault_dir] {
                if dir.is_dir() {
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                }
            }
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&cache)?;
        file.write_all(response.as_bytes())?;
        // Enforce 0600 even if the file already existed with looser permissions.
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    fs::write(&cache, response)?;

    Ok(())
}

/// Get the path to the cache file ~/.ssh/vault/keys/`<key>`
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
    fn test_get_cache_path() -> Result<(), Box<dyn std::error::Error>> {
        let cache = get_cache_path("test")?;
        assert!(!cache.is_dir());
        assert_eq!(
            cache.to_str(),
            get_home()?
                .join(".ssh")
                .join("vault")
                .join("keys")
                .join("test")
                .to_str()
        );
        Ok(())
    }

    #[test]
    fn test_get_ssh_vault_path() -> Result<(), Box<dyn std::error::Error>> {
        let ssh_vault = get_ssh_vault_path()?;
        assert!(!ssh_vault.is_file());
        assert_eq!(
            ssh_vault.to_str(),
            get_home()?.join(".ssh").join("vault").to_str()
        );
        Ok(())
    }

    #[test]
    fn test_put() -> Result<(), Box<dyn std::error::Error>> {
        let cache = get_cache_path("test-2")?;
        put("test-2", "test")?;

        assert!(cache.is_file());
        assert!(!cache.is_dir());
        assert!(cache.exists());
        assert_eq!(
            cache.to_str(),
            get_home()?
                .join(".ssh")
                .join("vault")
                .join("keys")
                .join("test-2")
                .to_str()
        );
        fs::remove_file(cache)?;
        Ok(())
    }

    #[test]
    fn test_get() -> Result<(), Box<dyn std::error::Error>> {
        let cache = get_cache_path("test-3")?;
        put("test-3", "test")?;
        let response = get("test-3")?;
        assert_eq!(response, "test");
        fs::remove_file(cache)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_put_permissions() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let cache = get_cache_path("test-perms")?;
        put("test-perms", "test")?;

        // Cache file must be owner-only (0600).
        let file_mode = fs::metadata(&cache)?.permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        // Parent directory must be owner-only (0700).
        if let Some(parent) = cache.parent() {
            let dir_mode = fs::metadata(parent)?.permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
        }

        fs::remove_file(cache)?;
        Ok(())
    }
}
