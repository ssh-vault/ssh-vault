package sshvault

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// View decrypts data and print it to stdout
func (v *vault) View() ([]byte, error) {
	file, err := os.Open(v.vault)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var (
		// ssh-vault;AES256;fingerprint
		header     []string
		rawPayload bytes.Buffer
	)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	l := 1
	for scanner.Scan() {
		line := scanner.Text()
		if l == 1 {
			header = strings.Split(line, ";")
		} else {
			rawPayload.WriteString(line)
		}
		l++
	}

	// password, body
	payload := strings.Split(rawPayload.String(), ";")

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
			return nil, fmt.Errorf("Password incorrect, Decryption failed.")
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload[0])
	if err != nil {
		return nil, err
	}

	v.password, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("Decryption failed, use private key with fingerprint: %s", v.Fingerprint)
	}

	ciphertext, err = base64.StdEncoding.DecodeString(payload[1])
	if err != nil {
		return nil, err
	}

	// decrypt ciphertext using fingerprint as additionalData
	data, err := v.Decrypt(ciphertext, []byte(header[2]))
	if err != nil {
		return nil, err
	}
	return data, nil
}
