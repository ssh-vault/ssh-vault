package sshvault

import (
	"fmt"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// GetPasswordPrompt ask for key passoword
func (v *vault) GetPasswordPrompt() ([]byte, error) {
	fmt.Printf("Enter the key password (%s)\n", v.key)
	keyPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	return keyPassword, nil
}
