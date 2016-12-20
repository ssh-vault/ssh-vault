// +build darwin

// Apple's OpenSSH fork uses Keychain for private key passphrases.
// They're indexed by the absolute file path to the private key,
// e.g. ~/.ssh/id_rsa
//
// If the passphrase isn't in keychain, prompt the user.

package sshvault

import (
	"fmt"
	"path/filepath"

  "github.com/keybase/go-keychain"
)

func (v *vault) GetPassword() ([]byte, error) {
  var keyPassword []byte

  key_path, err := filepath.Abs(v.key)
  if err != nil {
    return nil, fmt.Errorf("Error finding private key: %s", err)
  }

  keyPassword, err = keychain.GetGenericPassword("SSH", key_path, "", "")
  if err == nil {
    return keyPassword, nil
  }

  // Darn, Keychain doesn't have the password for that file. Prompt the user.
  keyPassword, err = v.GetPasswordPrompt()
  if err != nil {
    return nil, err
  }

  return keyPassword, nil
}
