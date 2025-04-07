# Changelog

## 1.1.0
* using `rsa::RsaPrivatekey::from_components` to create the private key from `ssh_key::PrivateKey::read_openssh_file`
* edition 2024

## 1.0.13
* bump versions, cargo update

## 1.0.7
* removed atty in favor of [std::io::IsTerminal](https://github.com/ssh-vault/ssh-vault/security/dependabot/7)
* using Zeroize

## 1.0.6
* display --help if no arguments are present
* Check if the path to save the vault is empty (prevent overwriting existing files)
* show examples only per command help not in main

## 1.0.5
* help templates/examples
* support for .config/ssh-vault/config.yml

## 1.0.4
* Added option `--input` to create a vault from an existing file

## 1.0.2
* Added option `--json` when creating a vault
* easy share using `echo "secret" | ssh-vault c -u new | pbcopy` copy & page to share the secret

## 1.0.0
* Support for ed25519 keys
* Legacy keys header (`-----BEGIN RSA PRIVATE KEY-----`) need to be updated using `ssh-keygen -p`
* moving to rust 🦀

## 0.12.8
* Support encrypted openssh private keys [#50](https://github.com/ssh-vault/ssh-vault/pull/50)

## 0.12.6
* Using crypto/ssh to match OpenSSH private key format (openssh-key-v1)

## 0.12.5
* Updated dependencies, thanks @iwittkau

## 0.12.4
* Improved lint
* Update GetPasswordPrompt message [#28](https://github.com/ssh-vault/ssh-vault/pull/28)
