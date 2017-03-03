package sshvault

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func (v *vault) GetPasswordPrompt() ([]byte, error) {
	fmt.Printf("Enter key password (%s)\n", v.key)
	keyPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	return keyPassword, nil
}
