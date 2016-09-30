package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	sv "github.com/ssh-vault/ssh-vault"
)

var version string

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
		fmt.Printf("Missing option, use (\"%s -h\") for help.\n", os.Args[0])
		os.Exit(1)
	}

	exit := true
	for _, v := range options {
		if flag.Arg(0) == v {
			exit = false
			break
		}
	}
	if exit {
		fmt.Printf("Invalid option, use (\"%s -h\") for help.\n", os.Args[0])
		os.Exit(1)
	}

	if flag.NArg() < 2 {
		fmt.Printf("Missing vault name, use (\"%s -h\") for help.\n", os.Args[0])
		os.Exit(1)
	}

	usr, _ := user.Current()
	if (*k)[:2] == "~/" {
		*k = filepath.Join(usr.HomeDir, (*k)[2:])
	}

	sv.New(*k, *u, flag.Arg(0), flag.Arg(1))
}
