use crate::tools;
use anyhow::{Context, Result};
use rsa::{RsaPublicKey, pkcs8::EncodePublicKey};
use ssh_key::{HashAlg, PublicKey};
use std::{fmt, fs, path::Path};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub key: String,
    pub fingerprints: Vec<String>,
    pub comment: String,
    pub algorithm: String,
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn format_fingerprint(fp: &str, width: usize) -> String {
            format!("{:>width$} {}", "", fp, width = width)
        }

        // Access custom width from the formatter arguments
        let custom_width = f.width().unwrap_or(self.key.len());

        writeln!(
            f,
            "{:>width$} Type: {} Comment: {}",
            self.key,
            self.algorithm,
            self.comment,
            width = custom_width
        )?;

        for fp in &self.fingerprints {
            writeln!(f, "{}", format_fingerprint(fp, custom_width))?;
        }

        Ok(())
    }
}

pub fn fingerprints() -> Result<Vec<Fingerprint>> {
    // Create a vector to store Fingerprint structs
    let mut fingerprints: Vec<Fingerprint> = Vec::new();

    let home = tools::get_home()?;
    let ssh_home = Path::new(&home).join(".ssh");
    if let Ok(entries) = fs::read_dir(ssh_home) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "pub" {
                    if let Ok(key) = PublicKey::read_openssh_file(&path) {
                        // Create a Fingerprint instance
                        let mut fingerprint = Fingerprint {
                            key: path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_string(),
                            comment: key.comment().to_string(),
                            algorithm: key.algorithm().to_string(),
                            ..Default::default()
                        };

                        fingerprint
                            .fingerprints
                            .push(key.fingerprint(HashAlg::Sha256).to_string());

                        if let Some(key_data) = key.key_data().rsa() {
                            let rsa_public_key = RsaPublicKey::try_from(key_data)?;
                            fingerprint
                                .fingerprints
                                .push(format!("MD5 {}", md5_fingerprint(&rsa_public_key)?));
                        }

                        fingerprints.push(fingerprint);
                    }
                }
            }
        }
    }
    Ok(fingerprints)
}

pub fn fingerprint(key: &str) -> Result<Fingerprint> {
    let path = Path::new(&key);
    let key = PublicKey::read_openssh_file(path)
        .context("Ensure you are passing a valid openssh public key")?;
    let mut fingerprint = Fingerprint {
        key: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        comment: key.comment().to_string(),
        algorithm: key.algorithm().to_string(),
        ..Default::default()
    };

    fingerprint
        .fingerprints
        .push(key.fingerprint(HashAlg::Sha256).to_string());

    if let Some(key_data) = key.key_data().rsa() {
        let rsa_public_key = RsaPublicKey::try_from(key_data)?;
        fingerprint
            .fingerprints
            .push(format!("MD5 {}", md5_fingerprint(&rsa_public_key)?));
    }

    Ok(fingerprint)
}

// Fetch the ssh keys from GitHub
pub fn get_remote_fingerprints(keys: &str, key: Option<u32>) -> Result<Vec<Fingerprint>> {
    // Get only SSH keys from the fetched keys
    let keys = tools::filter_fetched_keys(keys)?;

    // Create a vector to store Fingerprint structs
    let mut fingerprints: Vec<Fingerprint> = Vec::new();

    for (id, line) in keys.lines().enumerate() {
        let u32_id = u32::try_from(id)?;

        if let Some(mut key) = key {
            key = key.saturating_sub(1);

            if key >= u32::try_from(keys.lines().count())? {
                Err(anyhow::anyhow!(
                    "key index not found, try -k with a value between 1 and {}",
                    keys.lines().count()
                ))?;
            }
            if u32_id != key {
                continue;
            }
        }

        if let Ok(key) = PublicKey::from_openssh(line) {
            // Create a Fingerprint instance
            let mut fingerprint = Fingerprint {
                key: format!("ID: {}", id + 1),
                comment: key.comment().to_string(),
                algorithm: key.algorithm().to_string(),
                ..Default::default()
            };

            fingerprint
                .fingerprints
                .push(key.fingerprint(HashAlg::Sha256).to_string());

            if let Some(key_data) = key.key_data().rsa() {
                let rsa_public_key = RsaPublicKey::try_from(key_data)?;
                fingerprint
                    .fingerprints
                    .push(format!("MD5 {}", md5_fingerprint(&rsa_public_key)?));
            }

            fingerprints.push(fingerprint);
        }
    }

    Ok(fingerprints)
}

// Calculate the MD5 fingerprint of a RSA public key
// and format it as a colon separated string
pub fn md5_fingerprint(public_key: &RsaPublicKey) -> Result<String> {
    let public_key_der = public_key.to_public_key_der()?;
    let md5_fingerprint = md5::compute(public_key_der.as_bytes());
    let formatted_fingerprint = format!("{md5_fingerprint:x}")
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(":");
    Ok(formatted_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        key: &'static str,
        fingerprint: &'static str,
    }

    #[test]
    fn test_fingerprints() {
        let tests = [
            Test {
                key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDjjM4JEyg1T8j5YICtqslLNp2UGg80CppTM3ZYu73pEmDhMwbLfdhuI56AQZgWViFsF/7QHDJPcRY2Piu38b4kizTSM0QHEOC7CTo+vnzxptlKLGT1y2mcY1P9VXzCBMSWQN9/vGasgl/sUp1zcTvVT0CjjA6k1dJM6/+aDVtCsFa851VkwbeIsWl5BAHLyL+ur5BX93/BxYnRcYl7ooheuEWWokyWJ0IwEFToPMHAthTbDn1P17wYF43oscTORsFBfkP1JLBKHPDPJCGcBgQButL/srLJf6o44fScAYL99s1dQ/Qqv31aygDmwLdKEDldNnWEaJZ+iidEiIlPtAnLYGnVVA4u+NA2p3egrUrLWmpPjMX6XSb2VRHllzCcY4vZ4F2ud2TFaYG6N+9+vRCdxB+LFcHhm7ottI4vnC5P1bbMagjmFne0+TSKrAfMCw59eiQd8yZVMoE2yPXjFOQt6EOBvB4OHv1AaVt2q0PGqSkv5vIhgsKJWx/6IUj0Kz24hDiMipFb0jL3xstvizAllpC6yF26Ju/nwF03eJJGGxJjrxYd4P5/rY6SWY3yakiUN7pUBgUK2Ok3K3/+BTy5Aag8OXcvOZJumr2X2Wn9DweQeCRjC8UqFDKALqA/3vopZ2S59V4WOg3sV94hEig/KHLISNge1Uatn+qosK2sPw== test",
                fingerprint: "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15",
            },
            Test {
                key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCXsxWj7gvLUHbkUDzB6g+DfTdJbIcjH5Ge8ZZcYrTFeZ3hFL/pEfsuDf0Ut87QR0QpTFwM8SHyjKAX1rnF10Y+9ezG3Z4btHFk7SVPW0qqBwoTHFYiRqjgOcQrfQoDAhn9p/h93RCHR6gQPwj5CmDMRmnUcPV9mzjiLyqaqecAjGZj6q6O99Z5/lY2It/fCUcNW0JXBc31SiquvkkYhNjQsQgJxI5KnBMUEdVhk3ItJp8XeDbk2Kq03w0L8XcAqS2BUl4nNF4a5eMgME/tCUjSVYMvqcFIpOUsZhYNE+rt0ElbsMuehdvdLCbb2EBt+n75JgfGOsZCd96JrZiPlq55e0r5uDPz0rVtqnAWQawTtmSwa/VY7GZCf/xB2FvuqoXozWpAgzM7pypVx3JTBZwHx0xe/a0m1RA6+laQ4cCKV6FZWPV8WwUcvvxPknbDsjCeXgVQAxlXMk3pYrcGl61IPv/GaOr1QNPtUFRUuQXfgWh0F5SaU5MeI6HSGvuzooM=",
                fingerprint: "19:b9:77:30:3f:99:15:b7:53:98:0d:ef:d1:8f:33:58",
            },
            Test {
                key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdb5/i8sIEZ84k+LpJCAxRwxUZsP2MHFWApeB2TSUux ssh-vault",
                fingerprint: "SHA256:HcSHlMDnxnmeh6dsxdTrqOGUPp8Ei78VaF9t3ED21S8",
            },
            Test {
                key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINixf2m2nj8TDeazbWuemUY8ZHNg7znA7hVPN8TJLr2W",
                fingerprint: "SHA256:hgIL5fEHz5zuOWY1CDlUuotdaUl4MvYG7vAgE4q4TzM",
            },
        ];

        for test in tests.iter() {
            let mut fingerprint = String::new();
            let public_key = PublicKey::from_openssh(test.key).unwrap();
            if public_key.algorithm().as_str() == "ssh-rsa" {
                let key_data = public_key.key_data().rsa().unwrap();
                let rsa_public_key = RsaPublicKey::try_from(key_data).unwrap();
                fingerprint = md5_fingerprint(&rsa_public_key).unwrap();
            } else if public_key.algorithm().as_str() == "ssh-ed25519" {
                fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
            }
            assert_eq!(fingerprint, test.fingerprint);
        }
    }
}
