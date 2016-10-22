package sshvault

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ssh-vault/ssh2pem"
)

// Vault structure
type vault struct {
	key         string
	vault       string
	PublicKey   *rsa.PublicKey
	Fingerprint string
	Password    []byte
}

var isURL = regexp.MustCompile(`^https?://`)

// New initialize vault parameters
func New(k, u, o, v string) (*vault, error) {
	var (
		err     error
		keyPath string = k
	)
	cache := Cache()
	s := Locksmith{}
	if u != "" {
		// use -k N where N is the index to use when multiple keys
		// are available
		var ki int
		if ki, err = strconv.Atoi(k); err != nil {
			ki = 1
		}
		if ki <= 1 {
			ki = 1
		}
		keyPath, err = cache.Get(s, u, ki)
		if err != nil {
			return nil, err
		}
	} else if !cache.IsFile(keyPath) {
		return nil, fmt.Errorf("key not found or unable to read")
	}
	if o == "create" {
		if cache.IsFile(v) {
			return nil, fmt.Errorf("File already exists: %q", v)
		}
	}
	return &vault{
		key:   keyPath,
		vault: v,
	}, nil
}

// PKCS8 convert ssh public key to PEM PKCS8
func (v *vault) PKCS8() error {
	out, err := ssh2pem.GetPem(v.key)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(out)
	if p == nil {
		return fmt.Errorf("Could not create a PEM from the ssh key")
	}
	pubkeyInterface, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return err
	}
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
