package sshvault

import (
	"encoding/pem"
	"fmt"
	"os/exec"
)

// Vault structure
type vault struct {
	key    string
	option string
	vault  string
	pem    *pem.Block
}

// New initialize vault parameters
func New(k, u, o, v string) (*vault, error) {
	var (
		err     error
		keyPath string = k
	)
	cache := Cache()
	if u != "" {
		keyPath, err = cache.Get(u)
		if err != nil {
			return nil, err
		}
	} else if !cache.IsFile(keyPath) {
		return nil, fmt.Errorf("key not found or unable to read")
	}
	return &vault{
		key:    keyPath,
		option: o,
		vault:  v,
	}, nil
}

// PKCS8 convert ssh public key to PEM PKCS8
func (v *vault) PKCS8() error {
	out, err := exec.Command("ssh-keygen",
		"-f",
		v.key,
		"-e",
		"-m",
		"PKCS8").Output()
	if err != nil {
		return err
	}
	if v.pem, _ = pem.Decode(out); v.pem == nil {
		return fmt.Errorf("No PEM found")
	}
	return nil
}
