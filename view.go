package sshvault

import (
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
	file, err := ioutil.ReadFile(v.vault)
	if err != nil {
		return nil, err
	}
	vault := string(file)

	// header+payload
	parts := strings.Split(vault, "\n")

	// ssh-vault;AES256;fingerprint
	header := strings.Split(parts[0], ";")

	// password, body
	payload := strings.Split(parts[1], ";")

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

	ciphertext, err := hex.DecodeString(payload[0])
	if err != nil {
		return nil, err
	}

	v.password, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, []byte(""))
	if err != nil {
		return nil, err
	}

	ciphertext, err = hex.DecodeString(payload[1])
	if err != nil {
		return nil, err
	}

	// decrypt ciphertext using fingerpring as additionalData
	data, err := v.Decrypt(ciphertext, []byte(header[2]))
	if err != nil {
		return nil, err
	}
	return data, nil
}
