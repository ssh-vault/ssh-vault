package sshvault

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// GetPasswordPrompt ask for key password
func (v *vault) GetPasswordPrompt() ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Enter the key password (%s)\n", v.key)
	keyPassword, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}

	return keyPassword, nil
}
