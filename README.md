# ssh-vault
encrypt/decrypt using ssh private keys

Prototype working

    $ ssh-vault -h


To compile, after setting GOPATH etc, just type:

    $ make

Compiling for FreeBSD:

    env GOOS=freebsd GOARCH=amd64 go build -o ssh-vault cmd/ssh-vault/main.go

For Linux:

    env GOOS=linux GOARCH=amd64 go build -o ssh-vault cmd/ssh-vault/main.go
