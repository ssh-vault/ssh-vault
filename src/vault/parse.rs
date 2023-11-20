use anyhow::{anyhow, Result};
use base64ct::{Base64, Encoding};

// check if it's a valid SSH-VAULT file and return the data
pub fn parse(data: &str) -> Result<(&str, String, Vec<u8>, Vec<u8>)> {
    let tokens: Vec<_> = data.split(';').collect();

    if tokens[0] != "SSH-VAULT" || (tokens[1] != "AES256" && tokens[1] != "CHACHA20-POLY1305") {
        return Err(anyhow!("Not a valid SSH-VAULT file"));
    }

    if tokens[1] == "AES256" {
        if tokens.len() != 4 {
            return Err(anyhow!("Not a valid SSH-VAULT file"));
        }

        let mut lines = tokens[2].lines();

        let fingerprint = lines
            .next()
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?;

        let password = lines.collect::<Vec<&str>>().join("");
        let password = Base64::decode_vec(&password)?;

        lines = tokens[3].lines();

        let data = lines.collect::<Vec<&str>>().join("");
        let data = Base64::decode_vec(&data)?;

        return Ok((tokens[1], fingerprint.to_string(), password, data));
    } else if tokens[1] == "CHACHA20-POLY1305" {
        if tokens.len() != 6 {
            return Err(anyhow!("Not a valid SSH-VAULT file"));
        }

        let fingerprint = tokens[2].lines().collect::<Vec<&str>>().join("");

        let epk = tokens[3].lines().collect::<Vec<&str>>().join("");
        let epk = Base64::decode_vec(&epk)?;

        let password = tokens[4].lines().collect::<Vec<&str>>().join("");
        let password = Base64::decode_vec(&password)?;

        let mut epk_and_password = Vec::new();
        epk_and_password.extend_from_slice(&epk);
        epk_and_password.extend_from_slice(&password);

        let data = tokens[5].lines().collect::<Vec<&str>>().join("");
        let data = Base64::decode_vec(&data)?;

        return Ok((tokens[1], fingerprint, epk_and_password, data));
    }

    Err(anyhow!("Not a valid SSH-VAULT file"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_headers() {
        let data = r"SSH-VAULT:CHACHA20-POLY1305;0;0;0;0";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_parse_invalid_vault() {
        let data = r"SSH-VAULTCHACHA20-POLY1305SHA256:ZnlGYSmE8yBioOm+jhTxPAk4JagMu
mruoD1rf+WcpFY;EExFHBkGr4L2e0SS0y2Yw9lglLBGVmcho7r3EWSSZHU=;p3kQ
AVM09aZlRhfTZ4Gpp3WJ6AfurNqLo2Y8aDtQVj9uVx8FTJ+pVOTzphZMbCgzbSiU
pqwAZIHYhzss";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_parse_missing_data() {
        let data = r"SSH-VAULT;CHACHA20-POLY1305;SHA256:ZnlGYSmE8yBioOm+jhTxPAk4JagMu
mruoD1rf+WcpFY;EExFHBkGr4L2e0SS0y2Yw9lglLBGVmcho7r3EWSSZHU=;p3kQ
AVM09aZlRhfTZ4Gpp3WJ6AfurNqLo2Y8aDtQVj9uVx8FTJ+pVOTzphZMbCgzbSiU
pqwAZIHYhzss";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_parse_invalid_rsa_vault() {
        let data = r"SSH-VAULT;AES256;SHA256:ZnlGYSmE8yBioOm+jhTxPAk4JagMu";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_parse_no_fingerprint() {
        let data = r"SSH-VAULT;AES256";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_parse_no_payload() {
        let data = r"SSH-VAULT;AES256;;0";
        assert!(parse(data).is_err());
    }
}
