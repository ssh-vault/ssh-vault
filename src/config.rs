use crate::tools;
use anyhow::Result;
use config::Config;

pub fn get() -> Result<Config> {
    let home = tools::get_home()?;
    let config_file = home.join(".config").join("ssh-vault").join("config.yml");

    let builder = Config::builder()
        .add_source(config::Environment::with_prefix("SSH_VAULT"))
        .add_source(config::File::from(config_file));

    match builder.build() {
        Ok(config) => Ok(config),
        Err(_) => Ok(Config::builder()
            .add_source(config::Environment::with_prefix("SSH_VAULT"))
            .build()?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_get() {
        temp_env::with_vars([("SSH_VAULT_SSHKEYS_ONLINE", Some("localhost"))], || {
            let config = get().unwrap();
            assert_eq!(config.get_string("sshkeys_online").unwrap(), "localhost");
        });
    }
}
