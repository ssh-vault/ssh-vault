use crate::vault::{
    Vault, crypto::Crypto, crypto::aes256::Aes256Crypto, fingerprint::md5_fingerprint,
};
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use rand::rngs::OsRng;
use rsa::{BigUint, Oaep, RsaPrivateKey, RsaPublicKey};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;
use ssh_key::{PrivateKey, PublicKey, private::KeypairData, public::KeyData};
use zeroize::Zeroize;

#[derive(Debug)]
pub struct RsaVault {
    public_key: RsaPublicKey,
    private_key: Option<RsaPrivateKey>,
}

impl Vault for RsaVault {
    fn new(public: Option<PublicKey>, private: Option<PrivateKey>) -> Result<Self> {
        match (public, private) {
            (Some(public), None) => match public.key_data() {
                KeyData::Rsa(key_data) => {
                    let public_key =
                        RsaPublicKey::try_from(key_data).context("Could not load key")?;

                    Ok(Self {
                        public_key,
                        private_key: None,
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for RsaVault")),
            },

            (None, Some(private)) => match private.key_data() {
                KeypairData::Rsa(rsa_keypair) => {
                    if private.is_encrypted() {
                        return Err(anyhow::anyhow!("Private key is encrypted"));
                    }

                    // Extract components from ssh-key's RSA representation
                    // Use as_bytes() or a similar method to get the &[u8] from Mpint
                    //
                    // <https://docs.rs/ssh-key/latest/ssh_key/private/struct.RsaPrivateKey.html>
                    //
                    // pub struct RsaPrivateKey {
                    //     pub d: Mpint,
                    //     pub iqmp: Mpint,
                    //     pub p: Mpint,
                    //     pub q: Mpint,
                    // }
                    let modulus = BigUint::from_bytes_be(rsa_keypair.public.n.as_ref());
                    let public_exponent = BigUint::from_bytes_be(rsa_keypair.public.e.as_ref());
                    let private_exponent = BigUint::from_bytes_be(rsa_keypair.private.d.as_ref());
                    let prime_p = BigUint::from_bytes_be(rsa_keypair.private.p.as_ref());
                    let prime_q = BigUint::from_bytes_be(rsa_keypair.private.q.as_ref());

                    // Create the RSA private key
                    //
                    // Constructs an RSA key pair from individual components:
                    //
                    // n: RSA modulus
                    // e: public exponent (i.e. encrypting exponent)
                    // d: private exponent (i.e. decrypting exponent)
                    // primes: prime factors of n: typically two primes p and q. More than two
                    // primes can be provided for multiprime RSA, however this is generally not
                    // recommended. If no primes are provided, a prime factor recovery algorithm
                    // will be employed to attempt to recover the factors (as described in NIST SP
                    // 800-56B Revision 2 Appendix C.2). This algorithm only works if there are
                    // just two prime factors p and q (as opposed to multiprime), and e is between
                    // 2^16 and 2^256.
                    let private_key = RsaPrivateKey::from_components(
                        modulus,
                        public_exponent,
                        private_exponent,
                        vec![prime_p, prime_q],
                    )?;

                    // let private_key = RsaPrivateKey::try_from(key_data)?;

                    let public_key = private_key.to_public_key();

                    Ok(Self {
                        public_key,
                        private_key: Some(private_key),
                    })
                }
                _ => Err(anyhow::anyhow!("Invalid key type for RsaVault")),
            },

            (Some(_), Some(_)) => Err(anyhow::anyhow!(
                "Only one of public and private key is required"
            )),

            _ => Err(anyhow::anyhow!("Missing public and private key")),
        }
    }

    fn create(&self, password: SecretSlice<u8>, data: &mut [u8]) -> Result<String> {
        let crypto = Aes256Crypto::new(password.clone());

        let fingerprint = md5_fingerprint(&self.public_key)?;

        let encrypted_data = crypto.encrypt(data, fingerprint.as_bytes())?;

        // zeroize data
        data.zeroize();

        let encrypted_password =
            self.public_key
                .encrypt(&mut OsRng, Oaep::new::<Sha256>(), password.expose_secret())?;

        // create vault payload
        let payload = format!(
            "{};{}",
            Base64::encode_string(&encrypted_password),
            Base64::encode_string(&encrypted_data)
        )
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");

        Ok(format!("SSH-VAULT;AES256;{fingerprint}\n{payload}"))
    }

    fn view(&self, password: &[u8], data: &[u8], fingerprint: &str) -> Result<String> {
        let get_fingerprint = md5_fingerprint(&self.public_key)?;

        if get_fingerprint != fingerprint {
            return Err(anyhow::anyhow!("Fingerprint mismatch, use correct key"));
        }

        match &self.private_key {
            Some(private_key) => {
                let password: SecretSlice<u8> =
                    SecretSlice::new(private_key.decrypt(Oaep::new::<Sha256>(), password)?.into());

                let crypto = Aes256Crypto::new(password);

                let out = crypto.decrypt(data, fingerprint.as_bytes())?;
                Ok(String::from_utf8(out)?)
            }
            None => Err(anyhow::anyhow!("Private key is required to view vault")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;
    use anyhow::Result;
    use ssh_key::{PrivateKey, PublicKey};
    use std::path::Path;

    #[test]
    fn test_rsa_vault_using_both_keys() -> Result<()> {
        let public_key_file = Path::new("test_data/id_rsa.pub");
        let private_key_file = Path::new("test_data/id_rsa");
        let public_key = PublicKey::read_openssh_file(public_key_file)?;
        let private_key = PrivateKey::read_openssh_file(private_key_file)?;
        let vault = RsaVault::new(Some(public_key), Some(private_key));
        assert!(vault.is_err());

        let Err(err) = vault else {
            unreachable!("expected error when both keys provided")
        };

        // Convert the error to a string and check the message
        assert_eq!(
            err.to_string(),
            "Only one of public and private key is required"
        );

        Ok(())
    }

    #[test]
    fn test_rsa_vault_using_public_key() -> Result<()> {
        let public_key_file = Path::new("test_data/id_rsa.pub");
        let public_key = PublicKey::read_openssh_file(public_key_file)?;
        let vault = RsaVault::new(Some(public_key), None);
        assert!(vault.is_ok());
        Ok(())
    }

    #[test]
    fn test_rsa_vault_using_private_key() -> Result<()> {
        let private_key_file = Path::new("test_data/id_rsa");
        let private_key = PrivateKey::read_openssh_file(private_key_file)?;
        let vault = RsaVault::new(None, Some(private_key));
        assert!(vault.is_ok());
        Ok(())
    }
}
