package sshvault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/ssh-vault/crypto/oaep"
)

// Close saves encrypted data to file
func (v *vault) Close(data []byte) error {
	p, err := oaep.Encrypt(v.PublicKey, v.Password, []byte(""))
	if err != nil {
		return err
	}

	var payload bytes.Buffer
	payload.WriteString(base64.StdEncoding.EncodeToString(p))
	payload.WriteString(";")
	payload.WriteString(base64.StdEncoding.EncodeToString(data))

	vault := []byte(fmt.Sprintf("SSH-VAULT;AES256;%s\n%s\n",
		v.Fingerprint,
		v.Encode(payload.String(), 64)),
	)
	if v.vault != "" {
		return ioutil.WriteFile(v.vault, vault, 0600)
	}
	_, err = fmt.Printf("%s", vault)
	return err
}
