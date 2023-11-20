use clap::{builder::ValueParser, Arg, Command};
use regex::Regex;

const REGEX_MD5_FINGERPRINT: &str = r"^([0-9a-f]{2}:){15}([0-9a-f]{2})$";
const REGEX_SHA256_FINERPRINT: &str = r"^SHA256:[0-9a-zA-Z+/=]{43}$";

pub fn validator_fingerprint() -> ValueParser {
    ValueParser::from(move |s: &str| -> std::result::Result<String, String> {
        let md5 = Regex::new(REGEX_MD5_FINGERPRINT).unwrap();
        let sha256 = Regex::new(REGEX_SHA256_FINERPRINT).unwrap();

        if md5.is_match(s) || sha256.is_match(s) {
            Ok(s.to_owned())
        } else {
            Err("Invalid fingerprint".into())
        }
    })
}

pub fn subcommand_create() -> Command {
    Command::new("create")
        .about("Create a new vault")
        .after_help(
            r#"Examples:

Share a secret:

    echo "secret" | ssh-vault create -u new | pbcopy

Share a secret with a known user in GitHub:

    echo "secret" | ssh-vault create -u alice

Share a secret with Alice using its second key:

    echo "secret" | ssh-vault create -u alice -k 2
"#,
        )
        .visible_alias("c")
        .arg(
            Arg::new("fingerprint")
                .short('f')
                .long("fingerprint")
                .help("Create a vault using the key matching the specified fingerprint")
                .conflicts_with("key")
                .value_parser(validator_fingerprint()),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .help("Path to public ssh key or index when using option -u")
                .conflicts_with("fingerprint"),
        )
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .help("GitHub username or URL, optional [-k N] where N is the key index"),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("When using option -u and user 'new', output the vault in JSON format")
                .number_of_values(0),
        )
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .help("Create a vault form an existing file")
                .value_name("FILE"),
        )
        .arg(Arg::new("vault").help("file to store the vault or writes to stdout if not specified"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_regex() {
        let md5 = Regex::new(REGEX_MD5_FINGERPRINT).unwrap();
        let sha256 = Regex::new(REGEX_SHA256_FINERPRINT).unwrap();

        let tests = vec![
            "SHA256:27OFYkCe+dQ2OGAhR8rLjKONUWxPXyu5sTUftcrFAH0",
            "SHA256:manaBRGjdffWoXyg4cMwQ/+qj63c49VDk5UhwQGG1FY",
            "SHA256:hdQM6Q9D4wnXsoyB3K2RtoIPwHhtX1fJqe/ea+d3dFs",
            "SHA256:+aCsCTVZH7cp0cdFUE4QF8jv6D9v/4uax6/R/3mpvXY",
            "SHA256:l5q48gym0yQ0x0OJfgAa8GRxx1Ghc/AlnmkbsgF0qWs",
            "SHA256:glE01yuvgiVCRcnq1RUTJZT+8Z3f7XnG7F4jJtCtgZI",
            "SHA256:616UR76As6777hSo7ExLBQLtFE88LQCNegXcxynOTLs",
            "SHA256:YbZjcewAY5V78qWv/2fVEgEKTM4jWmJXVU7gonpJtLk",
            "SHA256:rCpb2a1l1vGHvEjsM3HsKm/mIpWmQy/3g0qDTLanpVA",
            "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:O09r+CSX4Ub8S3klaRp86ahCLbBkxhbaXW7v8y/ANCI",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:13",
        ];
        for test in tests.iter() {
            assert!(md5.is_match(test) || sha256.is_match(test));
        }
    }

    #[test]
    fn test_fingerprint_regex_invalid() {
        let md5 = Regex::new(REGEX_MD5_FINGERPRINT).unwrap();
        let sha256 = Regex::new(REGEX_SHA256_FINERPRINT).unwrap();

        let tests = vec![
            "SHA256:     27OFYkCe+dQ2OAhR8rLjKONUWxPXyu5sTUftcrFAH0",
            "SHA256: h0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:h0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:Nh0Me49Zh9fDw/VYUf]43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:Nh0Me49Zh9fDw/VYUf_43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:Nh0Me49Zh9fDw/VYUf 43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:Nh0Me49Zh9fDw/VYUf.43IJmI1T+XrjiYONPND8GzaM",
            "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM.",
            "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8Gza?",
            "SHA256:......................Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8=====",
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaNh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8=====",
            "SHA256manaBRGjdffWoXyg4cMwQ/+qj63c49VDk5UhwQGG1FY",
            "HA256:hdQM6Q9D4wnXsoyB3K2RtoIPwHhtX1fJqe/ea+d3dFs",
            "SHA256::+aCsCTVZH7cp0cdFUE4QF8jv6D9v/4uax6/R/3mpvXY",
            "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM.",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:1",
            "55cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:1",
            "55:cdf2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:1",
            "55:cd:f2:7e:4c:..:e5:a7:6e:6c:fc:6b:8e:58:9d:1",
            "55-cd-f2-7e-4c-0b-e5-a7-6e-6c-fc-6b-8e-58-9d::13",
            "55-cd-f2-7e-4c-0b-e5-a7-6e-6c-fc-6b-8e-58-9d-13",
        ];
        for test in tests.iter() {
            assert!(!(md5.is_match(test) || sha256.is_match(test)));
        }
    }

    #[test]
    fn test_subcommand_create_user_new_with_key_and_fingerprint() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "create",
            "-u",
            "new",
            "-k",
            "3",
            "-f",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:13",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_subcommand_create_with_fingerprint_1() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "create",
            "-u",
            "new",
            "-f",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:13",
        ]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_subcommand_create_with_fingerprint_2() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "create",
            "-u",
            "new",
            "-f",
            "SHA256:27OFYkCe+dQ2OGAhR8rLjKONUWxPXyu5sTUftcrFAH0",
        ]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_subcommand_create_with_bad_fingerprint() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "create",
            "-u",
            "new",
            "-f",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:1",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_subcommand_create_new_and_bad_fingerprint() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec![
            "ssh-vault",
            "create",
            "-u",
            "new",
            "-f",
            "55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:",
        ]);
        assert!(matches.is_err());
    }

    #[test]
    fn test_subcommand_create_with_key() {
        let app = Command::new("ssh-vault").subcommand(subcommand_create());
        let matches = app.try_get_matches_from(vec!["ssh-vault", "create", "-u", "new", "-k", "0"]);
        assert!(matches.is_ok());
    }
}
