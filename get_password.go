// +build !darwin

// For platforms without managed ssh private key passwords,
// fallback to prompting the user.

package sshvault

func (v *vault) GetPassword() ([]byte, error) {
	return v.GetPasswordPrompt()
}
