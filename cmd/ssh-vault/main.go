package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	sv "github.com/ssh-vault/ssh-vault"
)

var version string

func exit1(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func main() {
	var (
		k       = flag.String("k", "~/.ssh/id_rsa.pub", "public `ssh key`")
		u       = flag.String("u", "", "GitHub `username`")
		options = []string{"create", "decrypt", "edit", "encrypt", "view"}
		v       = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-k key] [-u user] [create|decrypt|edit|encrypt|view] vault\n\n%s\n%s\n%s\n%s\n%s\n%s\n\n",
			os.Args[0],
			"  Options:",
			"    create    creates a new vault",
			"    decrypt   decrypt a file",
			"    edit      open an existing vault",
			"    encrypt   encrypt a file",
			"    view      open an existing vault")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		exit1(fmt.Errorf("Missing option, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	exit := true
	for _, v := range options {
		if flag.Arg(0) == v {
			exit = false
			break
		}
	}
	if exit {
		exit1(fmt.Errorf("Invalid option, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	if flag.NArg() < 2 {
		exit1(fmt.Errorf("Missing vault name, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	usr, _ := user.Current()
	if (*k)[:2] == "~/" {
		*k = filepath.Join(usr.HomeDir, (*k)[2:])
	}

	vault, err := sv.New(*k, *u, flag.Arg(0), flag.Arg(1))
	if err != nil {
		exit1(err)
	}

	// ssh-keygen -f id_rsa.pub -e -m PKCS8
	if err := vault.PKCS8(); err != nil {
		exit1(err)
	}

	// generate password
	err = vault.GenPassword()
	if err != nil {
		exit1(err)
	}

	p, err := vault.EncryptPassword()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("p = %+v\n", p)

	/*
		// Write data to output file
		if err := ioutil.WriteFile("/tmp/test.vault", ciphertext, 0600); err != nil {
			log.Fatalf("write output: %s", err)
		}

		pem_data, err := ioutil.ReadFile("/tmp/priv-key.pem")
		if err != nil {
			log.Fatalf("Error reading pem file: %s", err)
		}
		block, _ := pem.Decode(pem_data)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			log.Fatal("No valid PEM data found")
		}
		private_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Private key can't be decoded: %s", err)
		}
		plainText, err := rsa.DecryptOAEP(hash, rand.Reader, private_key, ciphertext, label)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)

		//	openssl rsa -in xxxx
	*/
}
