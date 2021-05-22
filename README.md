# ssh-vault 🌰

[![build](https://github.com/ssh-vault/ssh-vault/actions/workflows/build.yml/badge.svg)](https://github.com/ssh-vault/ssh-vault/actions/workflows/build.yml)
[![test](https://github.com/ssh-vault/ssh-vault/actions/workflows/test.yml/badge.svg)](https://github.com/ssh-vault/ssh-vault/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/ssh-vault/ssh-vault/badge.svg?branch=develop)](https://coveralls.io/github/ssh-vault/ssh-vault?branch=develop)
[![Go Report Card](https://goreportcard.com/badge/github.com/ssh-vault/ssh-vault)](https://goreportcard.com/report/github.com/ssh-vault/ssh-vault)

encrypt/decrypt using ssh private keys

### Documentation

https://ssh-vault.com

### Usage

    $ ssh-vault -h

Example:

    $ echo "secret" | ssh-vault -u <github.com/user> create


## Installation

### Mac OS
    brew install ssh-vault

### Binaries
Binaries and packages for a variety of platforms are published to Bintray:
[ ![Download](https://api.bintray.com/packages/nbari/ssh-vault/ssh-vault/images/download.svg) ](https://dl.bintray.com/nbari/ssh-vault/)

To download specific version use URL like https://dl.bintray.com/nbari/ssh-vault/ssh-vault_0.12.4_amd64.deb

To download the latest version:

    PACKAGING=amd64.deb
    LATEST_VERSION=$(curl -w "%{redirect_url}" -o /dev/null -s https://bintray.com/nbari/ssh-vault/ssh-vault/_latestVersion | sed 's|.*/||')
    curl -L -O "https://dl.bintray.com/nbari/ssh-vault/ssh-vault_${LATEST_VERSION}_${PACKAGING}"

### Compile from source

Setup go environment https://golang.org/doc/install

For example using $HOME/go for your workspace

    $ export GOPATH=$HOME/go

Get the code:

    $ go get github.com/ssh-vault/ssh-vault

Build by just typing make:

    $ cd $GOPATH/src/github.com/ssh-vault/ssh-vault
    $ make

## Issues

Please feel free to raise any issue, feature requirement or a simple comment [here](https://github.com/ssh-vault/ssh-vault/issues).
