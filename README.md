# ssh-vault 🌰

[![Build Status](https://travis-ci.org/ssh-vault/ssh-vault.svg?branch=develop)](https://travis-ci.org/ssh-vault/ssh-vault)
[![Coverage Status](https://coveralls.io/repos/github/ssh-vault/ssh-vault/badge.svg?branch=develop)](https://coveralls.io/github/ssh-vault/ssh-vault?branch=develop)
[![Go Report Card](https://goreportcard.com/badge/github.com/ssh-vault/ssh-vault)](https://goreportcard.com/report/github.com/ssh-vault/ssh-vault)

encrypt/decrypt using ssh private keys

https://ssh-vault.com


Usage:

    $ ssh-vault -h


To compile, after setting GOPATH etc, just type:

    $ make

Compiling for FreeBSD:

    env GOOS=freebsd GOARCH=amd64 go build -o ssh-vault cmd/ssh-vault/main.go

For Linux:

    env GOOS=linux GOARCH=amd64 go build -o ssh-vault cmd/ssh-vault/main.go
