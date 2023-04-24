#!/bin/sh
#
# Create a file named vault.gpg with the password for your ssh private key
# and encrypt it with your GPG public key, example:
#
#   echo -n "secret" | gpg --output vault.gpg --encrypt --recipient your@email.tld
#
# Then run this script to decrypt the vault, example
#
#   ssh-vault v -k ./test_data/ed25519_password -p $(vaultpw.sh)

gpg --quiet --batch --decrypt vault.gpg
