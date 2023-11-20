use crate::{cache, config, tools, vault::fingerprint};
use anyhow::{anyhow, Result};
use reqwest::header::HeaderMap;
use rsa::RsaPublicKey;
use ssh_key::{HashAlg, PublicKey};
use std::collections::HashMap;
use url::Url;

const GITHUB_BASE_URL: &str = "https://github.com";
const SSHKEYS_ONLINE: &str = "https://ssh-keys.online/new";

// Fetch the ssh keys from GitHub
pub fn get_keys(user: &str) -> Result<String> {
    let mut cache = true;

    let url = if user.starts_with("http://") || user.starts_with("https://") {
        Url::parse(user)?
    } else if user == "new" {
        cache = false;

        // get the config from ~/.config/ssh-vault/config.yml
        let config = config::get()?;

        Url::parse(
            &config
                .get_string("sshkeys_online")
                .unwrap_or_else(|_| String::from(SSHKEYS_ONLINE)),
        )?
    } else {
        Url::parse(&format!("{GITHUB_BASE_URL}/{user}.keys"))?
    };

    request(url.as_str(), cache)
}

pub fn request(url: &str, cache: bool) -> Result<String> {
    let url = Url::parse(url)?;

    let cache_key = format!("{:x}", md5::compute(url.as_str().as_bytes()));

    // load from cache
    if let Ok(key) = cache::get(&cache_key) {
        Ok(key)
    } else {
        // get the headers
        let headers: HeaderMap = get_headers()?;

        // Create a client
        let client = reqwest::blocking::Client::builder()
            .user_agent("ssh-vault")
            .default_headers(headers)
            .build()?;

        // Make a GET request
        let res = client.get(url).send()?;

        if res.status().is_success() {
            // Read the response body
            let body = res.text()?;

            if cache {
                cache::put(&cache_key, &body)?;
            }
            Ok(body)
        } else {
            Err(anyhow!("Request failed with status: {}", res.status()))
        }
    }
}

// Get the HTTP headers from the config
fn get_headers() -> Result<HeaderMap> {
    let mut config_headers: HashMap<String, String> = HashMap::new();

    // get the config from ~/.config/ssh-vault/config.yml
    let config = config::get()?;

    if let Ok(http_headers) = config.get_table("http_headers") {
        for (key, value) in &http_headers {
            config_headers.insert(key.to_string(), value.to_string());
        }
    }

    let headers: HeaderMap = (&config_headers).try_into().unwrap_or_default();

    Ok(headers)
}

// Get the user key from the fetched keys
pub fn get_user_key(
    keys: &str,
    key: Option<u32>,
    fingerprint: Option<String>,
) -> Result<PublicKey> {
    // Get only SSH keys from the fetched keys
    let keys = tools::filter_fetched_keys(keys)?;

    let key = key.map_or(0, |mut key| {
        key = key.saturating_sub(1);
        key
    });

    for (id, line) in keys.lines().enumerate() {
        let u32_id = u32::try_from(id)?;
        if key >= u32::try_from(keys.lines().count())? {
            Err(anyhow!(
                "key index not found, try -k with a value between 1 and {}",
                keys.lines().count()
            ))?;
        }

        // parse the line as a public key
        if let Ok(public_key) = PublicKey::from_openssh(line) {
            // if fingerprint is provided, check if it matches
            if let Some(f) = &fingerprint {
                if public_key.fingerprint(HashAlg::Sha256).to_string() == *f {
                    return Ok(public_key);
                }

                // get the MD5 fingerprint
                if let Some(key_data) = public_key.key_data().rsa() {
                    let rsa_public_key = RsaPublicKey::try_from(key_data)?;
                    if fingerprint::md5_fingerprint(&rsa_public_key)?.as_bytes() == f.as_bytes() {
                        return Ok(public_key);
                    }
                }
            } else if u32_id == key {
                return Ok(public_key);
            }
        }
    }

    Err(anyhow!("key not found"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::fingerprint::get_remote_fingerprints;
    use crate::vault::fingerprint::Fingerprint;

    const KEYS: &str = "
# random comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDjjM4JEyg1T8j5YICtqslLNp2UGg80CppTM3ZYu73pEmDhMwbLfdhuI56AQZgWViFsF/7QHDJPcRY2Piu38b4kizTSM0QHEOC7CTo+vnzxptlKLGT1y2mcY1P9VXzCBMSWQN9/vGasgl/sUp1zcTvVT0CjjA6k1dJM6/+aDVtCsFa851VkwbeIsWl5BAHLyL+ur5BX93/BxYnRcYl7ooheuEWWokyWJ0IwEFToPMHAthTbDn1P17wYF43oscTORsFBfkP1JLBKHPDPJCGcBgQButL/srLJf6o44fScAYL99s1dQ/Qqv31aygDmwLdKEDldNnWEaJZ+iidEiIlPtAnLYGnVVA4u+NA2p3egrUrLWmpPjMX6XSb2VRHllzCcY4vZ4F2ud2TFaYG6N+9+vRCdxB+LFcHhm7ottI4vnC5P1bbMagjmFne0+TSKrAfMCw59eiQd8yZVMoE2yPXjFOQt6EOBvB4OHv1AaVt2q0PGqSkv5vIhgsKJWx/6IUj0Kz24hDiMipFb0jL3xstvizAllpC6yF26Ju/nwF03eJJGGxJjrxYd4P5/rY6SWY3yakiUN7pUBgUK2Ok3K3/+BTy5Aag8OXcvOZJumr2X2Wn9DweQeCRjC8UqFDKALqA/3vopZ2S59V4WOg3sV94hEig/KHLISNge1Uatn+qosK2sPw==
# another random comment
space

# another random comment
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCXsxWj7gvLUHbkUDzB6g+DfTdJbIcjH5Ge8ZZcYrTFeZ3hFL/pEfsuDf0Ut87QR0QpTFwM8SHyjKAX1rnF10Y+9ezG3Z4btHFk7SVPW0qqBwoTHFYiRqjgOcQrfQoDAhn9p/h93RCHR6gQPwj5CmDMRmnUcPV9mzjiLyqaqecAjGZj6q6O99Z5/lY2It/fCUcNW0JXBc31SiquvkkYhNjQsQgJxI5KnBMUEdVhk3ItJp8XeDbk2Kq03w0L8XcAqS2BUl4nNF4a5eMgME/tCUjSVYMvqcFIpOUsZhYNE+rt0ElbsMuehdvdLCbb2EBt+n75JgfGOsZCd96JrZiPlq55e0r5uDPz0rVtqnAWQawTtmSwa/VY7GZCf/xB2FvuqoXozWpAgzM7pypVx3JTBZwHx0xe/a0m1RA6+laQ4cCKV6FZWPV8WwUcvvxPknbDsjCeXgVQAxlXMk3pYrcGl61IPv/GaOr1QNPtUFRUuQXfgWh0F5SaU5MeI6HSGvuzooM= vault@ssh-vault.online
---
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINixf2m2nj8TDeazbWuemUY8ZHNg7znA7hVPN8TJLr2W
+++
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdb5/i8sIEZ84k+LpJCAxRwxUZsP2MHFWApeB2TSUux ssh-vault

Fin
";

    fn get_expected() -> Vec<Fingerprint> {
        vec![
            Fingerprint {
                key: "ID: 1".to_string(),
                fingerprints: vec![
                    "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string(),
                    "MD5 55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15".to_string(),
                ],
                comment: "".to_string(),
                algorithm: "ssh-rsa".to_string(),
            },
            Fingerprint {
                key: "ID: 2".to_string(),
                fingerprints: vec![
                    "SHA256:O09r+CSX4Ub8S3klaRp86ahCLbBkxhbaXW7v8y/ANCI".to_string(),
                    "MD5 19:b9:77:30:3f:99:15:b7:53:98:0d:ef:d1:8f:33:58".to_string(),
                ],
                comment: "vault@ssh-vault.online".to_string(),
                algorithm: "ssh-rsa".to_string(),
            },
            Fingerprint {
                key: "ID: 3".to_string(),
                fingerprints: vec!["SHA256:hgIL5fEHz5zuOWY1CDlUuotdaUl4MvYG7vAgE4q4TzM".to_string()],
                comment: "".to_string(),
                algorithm: "ssh-ed25519".to_string(),
            },
            Fingerprint {
                key: "ID: 4".to_string(),
                fingerprints: vec!["SHA256:HcSHlMDnxnmeh6dsxdTrqOGUPp8Ei78VaF9t3ED21S8".to_string()],
                comment: "ssh-vault".to_string(),
                algorithm: "ssh-ed25519".to_string(),
            },
        ]
    }

    #[test]
    fn test_get_remote_fingerprints() {
        let f = get_remote_fingerprints(KEYS, None).unwrap();
        assert_eq!(f, get_expected());
    }

    #[test]
    fn test_get_remote_fingerprints_with_key() {
        for i in 1..=4 {
            assert_eq!(
                get_expected()[i - 1],
                get_remote_fingerprints(KEYS, Some(i as u32)).unwrap()[0]
            )
        }
    }

    #[test]
    fn test_get_remote_fingerprints_with_key_0_1() {
        // key 0 and 1 should be the same
        assert_eq!(
            get_expected()[0],
            get_remote_fingerprints(KEYS, Some(0)).unwrap()[0]
        );

        assert_eq!(
            get_expected()[0],
            get_remote_fingerprints(KEYS, Some(1)).unwrap()[0]
        );

        // ensure key 0 and 1 are not the same as key 2
        assert_ne!(
            get_expected()[0],
            get_remote_fingerprints(KEYS, Some(2)).unwrap()[0]
        );
    }

    #[test]
    fn test_get_remote_fingerprints_with_empty_keys() {
        assert!(get_remote_fingerprints(KEYS, Some(10)).is_err());
        assert!(get_remote_fingerprints("", None).is_err());
        assert!(get_remote_fingerprints("", Some(1)).is_err());
    }

    #[test]
    fn test_get_user_key() {
        let key = get_user_key(KEYS, Some(1), None).unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );
    }

    #[test]
    fn test_get_user_key_3() {
        let key = get_user_key(KEYS, Some(3), None).unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:hgIL5fEHz5zuOWY1CDlUuotdaUl4MvYG7vAgE4q4TzM".to_string()
        );
    }

    #[test]
    fn test_get_user_key_0_1() {
        // key 0 and 1 should be the same
        let key = get_user_key(KEYS, None, None).unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );
        let key = get_user_key(KEYS, Some(0), None).unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );
        let key = get_user_key(KEYS, Some(1), None).unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );
    }

    #[test]
    fn test_get_user_key_with_fingerprint() {
        let key = get_user_key(
            KEYS,
            None,
            Some("SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()),
        )
        .unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );
    }

    #[test]
    fn test_get_user_key_with_fingerprint_md5_rsa() {
        let key = get_user_key(
            KEYS,
            None,
            Some("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15".to_string()),
        )
        .unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:12mLJQInCFoL9JOPJwPGb/FUEe459PY1yZEZqNGVZtA".to_string()
        );

        let key = get_user_key(
            KEYS,
            None,
            Some("19:b9:77:30:3f:99:15:b7:53:98:0d:ef:d1:8f:33:58".to_string()),
        )
        .unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            "SHA256:O09r+CSX4Ub8S3klaRp86ahCLbBkxhbaXW7v8y/ANCI".to_string()
        );
    }

    #[test]
    fn test_get_user_key_with_empty_keys() {
        assert!(get_user_key("", Some(10), None).is_err());
        assert!(get_user_key("", None, None).is_err());
        assert!(get_user_key("", Some(1), None).is_err());
    }

    #[test]
    fn test_get_user_key_with_key_out_of_range() {
        assert!(get_user_key(KEYS, Some(10), None).is_err());
    }

    #[test]
    fn test_get_headers() {
        let headers = get_headers().unwrap();
        assert!(headers.is_empty());
    }
}
