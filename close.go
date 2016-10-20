package sshvault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

// Close saves encrypted data to file
func (v *vault) Close(data []byte) error {
	p, err := v.EncryptPassword()
	if err != nil {
		return err
	}

	var payload bytes.Buffer
	payload.WriteString(base64.StdEncoding.EncodeToString(p))
	payload.WriteString(";")
	payload.WriteString(base64.StdEncoding.EncodeToString(data))

	err = ioutil.WriteFile(v.vault,
		[]byte(fmt.Sprintf("SSH-VAULT;AES256;%s\n%s\n",
			v.Fingerprint,
			v.Encode(payload.String(), 64))),
		0600,
	)
	if err != nil {
		return err
	}
	return nil
}
