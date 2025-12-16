use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};

/// Check if it's a valid SSH-VAULT file and return the parsed components.
///
/// # Errors
///
/// Returns an error if the input is malformed or any Base64 decoding fails.
pub fn parse(data: &str) -> Result<(&str, String, Vec<u8>, Vec<u8>)> {
    let tokens: Vec<_> = data.split(';').collect();

    let vault_marker = tokens
        .first()
        .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?;
    let algorithm = tokens
        .get(1)
        .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?;

    if *vault_marker != "SSH-VAULT" || (*algorithm != "AES256" && *algorithm != "CHACHA20-POLY1305")
    {
        return Err(anyhow!("Not a valid SSH-VAULT file"));
    }

    if *algorithm == "AES256" {
        if tokens.len() != 4 {
            return Err(anyhow!("Not a valid SSH-VAULT file"));
        }

        let mut lines = tokens
            .get(2)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines();

        let fingerprint = lines
            .next()
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?;

        let password = lines.collect::<Vec<&str>>().join("");
        let password = Base64::decode_vec(&password)?;

        lines = tokens
            .get(3)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines();

        let data = lines.collect::<Vec<&str>>().join("");
        let data = Base64::decode_vec(&data)?;

        return Ok((algorithm, fingerprint.to_string(), password, data));
    } else if *algorithm == "CHACHA20-POLY1305" {
        if tokens.len() != 6 {
            return Err(anyhow!("Not a valid SSH-VAULT file"));
        }

        let fingerprint = tokens
            .get(2)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines()
            .collect::<Vec<&str>>()
            .join("");

        let epk = tokens
            .get(3)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines()
            .collect::<Vec<&str>>()
            .join("");
        let epk = Base64::decode_vec(&epk)?;

        let password = tokens
            .get(4)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines()
            .collect::<Vec<&str>>()
            .join("");
        let password = Base64::decode_vec(&password)?;

        let mut epk_and_password = Vec::new();
        epk_and_password.extend_from_slice(&epk);
        epk_and_password.extend_from_slice(&password);

        let data = tokens
            .get(5)
            .ok_or_else(|| anyhow!("Not a valid SSH-VAULT file"))?
            .lines()
            .collect::<Vec<&str>>()
            .join("");
        let data = Base64::decode_vec(&data)?;

        return Ok((algorithm, fingerprint, epk_and_password, data));
    }

    Err(anyhow!("Not a valid SSH-VAULT file"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn test_parse_empty_string() {
        let data = "";
        let result = parse(data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Not a valid SSH-VAULT file")
        );
    }

    #[test]
    fn test_parse_single_token() {
        let data = "SSH-VAULT";
        let result = parse(data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Not a valid SSH-VAULT file")
        );
    }

    #[test]
    fn test_parse_no_tokens() {
        let data = ";";
        let result = parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_malformed_header() {
        let data = "INVALID";
        let result = parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wrong_crypto_type() {
        let data = "SSH-VAULT;INVALID_CRYPTO";
        let result = parse(data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Not a valid SSH-VAULT file")
        );
    }
}
