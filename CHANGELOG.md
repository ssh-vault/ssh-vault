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
