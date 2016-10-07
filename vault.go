package sshvault

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
)

// Vault structure
type vault struct {
	key         string
	option      string
	vault       string
	PublicKey   *rsa.PublicKey
	Fingerprint string
	password    []byte
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
		return fmt.Errorf("Error creating PKCS8: %q try again", err)
	}
	p, _ := pem.Decode(out)
	if p == nil {
		return fmt.Errorf("No PEM found")
	}
	pubkeyInterface, err := x509.ParsePKIXPublicKey(p.Bytes)
	var ok bool
	v.PublicKey, ok = pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("No Public key found")
	}
	fingerPrint := md5.New()
	fingerPrint.Write(p.Bytes)
	v.Fingerprint = strings.Replace(fmt.Sprintf("% x",
		fingerPrint.Sum(nil)),
		" ",
		":",
		-1)
	return nil
}

// GenPassword return a slice of 32 random bytes
func (v *vault) GenPassword() error {
	v.password = make([]byte, 32)
	_, err := rand.Read(v.password)
	if err != nil {
		return err
	}
	return nil
}

// GenPassword create password using Rand32
// and use the ssh public key to encrypt it
func (v *vault) EncryptPassword() ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(),
		rand.Reader,
		v.PublicKey,
		v.password,
		[]byte(""))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
