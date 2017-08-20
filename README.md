# ssh-vault 🌰

[![Build Status](https://travis-ci.org/ssh-vault/ssh-vault.svg?branch=develop)](https://travis-ci.org/ssh-vault/ssh-vault)
[![Coverage Status](https://coveralls.io/repos/github/ssh-vault/ssh-vault/badge.svg?branch=develop)](https://coveralls.io/github/ssh-vault/ssh-vault?branch=develop)
[![Go Report Card](https://goreportcard.com/badge/github.com/ssh-vault/ssh-vault)](https://goreportcard.com/report/github.com/ssh-vault/ssh-vault)

encrypt/decrypt using ssh private keys

https://ssh-vault.com

[ ![Download](https://api.bintray.com/packages/nbari/ssh-vault/ssh-vault/images/download.svg) ](https://dl.bintray.com/nbari/ssh-vault/)


Usage:

    $ ssh-vault -h

Example:

    $ echo "secret" | ssh-vault -u <github.com/user> create


## Compile from source

Setup go environment https://golang.org/doc/install

For example using $HOME/go for your workspace

    $ export GOPATH=$HOME/go

Create the directory:

    $ mkdir -p $HOME/go/src/github.com/ssh-vault

Clone project into that directory:

    $ git clone git@github.com:ssh-vault/ssh-vault.git $HOME/go/src/github.com/ssh-vault/ssh-vault

Build by just typing make:

    $ cd $HOME/go/src/github.com/ssh-vault/ssh-vault
    $ make


## Issues

Please feel free to raise any issue, feature requirement or a simple comment [here](https://github.com/ssh-vault/ssh-vault/issues).
