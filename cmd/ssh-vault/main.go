package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
	sv "github.com/ssh-vault/ssh-vault"
)

var version string

func exit1(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func main() {
	var (
		k       = flag.String("k", "~/.ssh/id_rsa.pub", "Public `ssh key or index` when using option -u")
		u       = flag.String("u", "", "GitHub `username or URL`, optional [-k N] where N is the key index to use")
		f       = flag.Bool("f", false, "Print ssh key `fingerprint`")
		options = []string{"create", "edit", "view"}
		v       = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-k key] [-u user] [create|edit|view] vault\n\n%s\n%s\n%s\n%s\n\n",
			os.Args[0],
			"  Options:",
			"    create    Creates a new vault",
			"    edit      Edit an existing vault",
			"    view      View an existing vault")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *v {
		fmt.Printf("%s - ssh-vault.com\n", version)
		os.Exit(0)
	}

	usr, _ := user.Current()
	if len(*k) > 2 {
		if (*k)[:2] == "~/" {
			*k = filepath.Join(usr.HomeDir, (*k)[2:])
		}
	}

	vault, err := sv.New(*k, *u, flag.Arg(0), flag.Arg(1))
	if err != nil {
		exit1(fmt.Errorf("%s, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	// ssh-keygen -f id_rsa.pub -e -m PKCS8
	if err := vault.PKCS8(); err != nil {
		exit1(fmt.Errorf("%s, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	// print fingerprint and exit
	if *f {
		fmt.Println(vault.Fingerprint)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		exit1(fmt.Errorf("Missing option, use (\"%s -h\") for help.\n", os.Args[0]))
	}
	// check options
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

	// check for vault name
	if flag.NArg() < 2 {
		exit1(fmt.Errorf("Missing vault name, use (\"%s -h\") for help.\n", os.Args[0]))
	}

	vault.Password, err = crypto.GenerateNonce(32)
	if err != nil {
		exit1(err)
	}

	switch flag.Arg(0) {
	case "create":
		data, err := vault.Create()
		if err != nil {
			exit1(err)
		}
		out, err := aead.Encrypt(vault.Password, data, []byte(vault.Fingerprint))
		if err != nil {
			exit1(err)
		}
		err = vault.Close(out)
		if err != nil {
			exit1(err)
		}
	case "edit":
		data, err := vault.View()
		if err != nil {
			exit1(err)
		}
		out, err := vault.Edit(data)
		if err != nil {
			exit1(err)
		}
		out, err = aead.Encrypt(vault.Password, out, []byte(vault.Fingerprint))
		if err != nil {
			exit1(err)
		}
		err = vault.Close(out)
		if err != nil {
			exit1(err)
		}
	case "view":
		out, err := vault.View()
		if err != nil {
			exit1(err)
		}
		fmt.Printf("\n%s", out)
	}
}
