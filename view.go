package sshvault

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// View decrypts data and print it to stdout
func (v *vault) View() ([]byte, error) {
	vault, err := ioutil.ReadFile(v.vault)
	if err != nil {
		return nil, err
	}

	// head, password, body
	parts := bytes.Split(vault, []byte("\n"))

	// use private key only
	if strings.HasSuffix(v.key, ".pub") {
		v.key = strings.Trim(v.key, ".pub")
	}

	keyFile, err := ioutil.ReadFile(v.key)
	if err != nil {
		return nil, fmt.Errorf("Error reading private key: %s", err)
	}

	block, _ := pem.Decode(keyFile)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("No valid PEM (private key) data found")
	}

	if x509.IsEncryptedPEMBlock(block) {
		fmt.Print("Enter key password: ")
		keyPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		fmt.Println()
		block.Bytes, err = x509.DecryptPEMBlock(block, keyPassword)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, hex.DecodedLen(len(parts[1])))
	_, err = hex.Decode(ciphertext, parts[1])
	if err != nil {
		return nil, err
	}

	v.password, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, []byte(""))
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, hex.DecodedLen(len(parts[2])))
	_, err = hex.Decode(ciphertext, parts[2])
	if err != nil {
		return nil, err
	}

	data, err := v.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return data, nil
}
