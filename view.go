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
	"log"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// View decrypts data and print it to stdout
func (v *vault) View() error {
	vault, err := ioutil.ReadFile(v.vault)
	if err != nil {
		return err
	}
	// head, pass, body
	parts := bytes.Split(vault, []byte("\n"))

	// get pem
	pemData, err := ioutil.ReadFile(v.key)
	if err != nil {
		log.Fatalf("Error reading pem file: %s", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("No valid PEM (private key) data found")
	}
	var pemOut []byte
	if x509.IsEncryptedPEMBlock(block) {
		fmt.Print("Enter key password: ")
		keyPassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return err
		}
		pemOut, err = x509.DecryptPEMBlock(block, keyPassword)
		if err != nil {
			return err
		}
	} else {
		pemOut = block.Bytes
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(pemOut)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, hex.DecodedLen(len(parts[1])))
	_, err = hex.Decode(ciphertext, parts[1])
	if err != nil {
		return err
	}

	v.password, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, []byte(""))
	if err != nil {
		return err
	}

	ciphertext = make([]byte, hex.DecodedLen(len(parts[2])))
	_, err = hex.Decode(ciphertext, parts[2])
	if err != nil {
		return err
	}
	data, err := v.Decrypt(ciphertext)
	if err != nil {
		return err
	}
	fmt.Printf("\n%s", data)
	return nil
}
