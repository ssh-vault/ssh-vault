package sshvault

import (
	"fmt"
	"io/ioutil"
)

// Close saves encrypted data to file
func (v *vault) Close(data []byte) error {
	p, err := v.EncryptPassword()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(v.vault,
		[]byte(fmt.Sprintf("$SSH-VAULT;AES256;%s\n%x\n%x",
			v.Fingerprint,
			p,
			data)),
		0600,
	)
	if err != nil {
		return err
	}
	return nil
}
