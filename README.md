# ssh-vault 🌰

[![test](https://github.com/ssh-vault/ssh-vault/actions/workflows/test.yml/badge.svg)](https://github.com/ssh-vault/ssh-vault/actions/workflows/test.yml)

encrypt/decrypt using ssh private keys

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
