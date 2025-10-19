# ssh-vault 🌰

[![Test & Build](https://github.com/ssh-vault/ssh-vault/actions/workflows/build.yml/badge.svg)](https://github.com/ssh-vault/ssh-vault/actions/workflows/build.yml)
[![Security Audit](https://github.com/ssh-vault/ssh-vault/actions/workflows/security-audit.yml/badge.svg)](https://github.com/ssh-vault/ssh-vault/actions/workflows/security-audit.yml)
[![codecov](https://codecov.io/gh/ssh-vault/ssh-vault/graph/badge.svg?token=cWvIQCym2l)](https://codecov.io/gh/ssh-vault/ssh-vault)
[![crates.io](https://img.shields.io/crates/v/ssh-vault.svg)](https://crates.io/crates/ssh-vault)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

encrypt/decrypt using ssh keys

### Documentation

https://ssh-vault.com

> The legacy SSH RSA keys with header `-----BEGIN RSA PRIVATE KEY-----` are not any more supported, convert your key to new format with:

    ssh-keygen -p -f <path/to/your/private.key>

### Usage

    $ ssh-vault -h


```txt
encrypt/decrypt using ssh keys

Usage: ssh-vault [COMMAND]

Commands:
  create       Create a new vault [aliases: c]
  edit         Edit an existing vault [aliases: e]
  fingerprint  Print the fingerprint of a public ssh key [aliases: f]
  view         View an existing vault [aliases: v]
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

```

Examples:


Create a vault:


```sh
$ echo "secret" | ssh-vault create -u <github.com/user>
```

View a vault:

```sh
echo "SSH-VAULT..."| ssh-vault view
```

Share a secret:

```sh
$ echo "secret" | ssh-vault create -u new
```


## Installation

### Mac OS
    brew install ssh-vault

### Using Cargo

    $ cargo install ssh-vault

## Issues

Please feel free to raise any issue, feature requirement or a simple comment [here](https://github.com/ssh-vault/ssh-vault/issues).
