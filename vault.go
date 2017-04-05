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
	Password    []byte
	PublicKey   *rsa.PublicKey
	Fingerprint string
	key         string
	vault       string
}

// GITHUB  https://github.com/<username>.keys
const GITHUB = "https://github.com"

// isURL regex to match if user is an URL
var isURL = regexp.MustCompile(`^https?://`)

// New initialize vault parameters
func New(f, k, u, o, v string) (*vault, error) {
	var (
		err     error
		keyPath string = k
	)
	cache := Cache()
	s := Locksmith{GITHUB}
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
		keyPath, err = cache.Get(s, u, f, ki)
		if err != nil {
			return nil, err
		}
	} else if !cache.IsFile(keyPath) {
		return nil, fmt.Errorf("SSH key %q not found or unable to read", keyPath)
	}
	if o == "create" {
		if v != "" && cache.IsFile(v) {
			return nil, fmt.Errorf("File already exists: %q", v)
		}
	}
	return &vault{
		key:   keyPath,
		vault: v,
	}, nil
}

// PKCS8 convert ssh public key to PEM PKCS8
func (v *vault) PKCS8() (*pem.Block, error) {
	out, err := ssh2pem.GetPem(v.key)
	if err != nil {
		return nil, err
	}
	p, rest := pem.Decode(out)
	if p == nil {
		return nil, fmt.Errorf("Could not create a PEM from the ssh key, %q", rest)
	}
	return p, nil
}

// Fingerprint return finerprint of ssh-key
func (v *vault) GenFingerprint(p *pem.Block) (string, error) {
	fingerPrint := md5.New()
	fingerPrint.Write(p.Bytes)
	return strings.Replace(fmt.Sprintf("% x",
		fingerPrint.Sum(nil)),
		" ",
		":",
		-1), nil
}

// GetRSAPublicKey return rsa.PublicKey
func (v *vault) GetRSAPublicKey(p *pem.Block) (*rsa.PublicKey, error) {
	pubkeyInterface, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("No Public key found")
	}
	return rsaPublicKey, nil
}
