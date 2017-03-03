package sshvault

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/ssh-vault/crypto/aead"
	"github.com/ssh-vault/crypto/oaep"
)

// View decrypts data and print it to stdout
func (v *vault) View() ([]byte, error) {
	var (
		header     []string
		rawPayload bytes.Buffer
		scanner    *bufio.Scanner
	)

	// check if there is someting to read on STDIN
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(v.vault)
		if err != nil {
			return nil, fmt.Errorf("Missing vault name, use (\"%s -h\") for help.\n", os.Args[0])
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
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

	// ssh-vault;AES256;fingerprint
	if len(header) != 3 {
		return nil, fmt.Errorf("Bad ssh-vault signature, verify the input\n")
	}

	// password, body
	payload := strings.Split(rawPayload.String(), ";")
	if len(payload) != 2 {
		return nil, fmt.Errorf("Bad ssh-vault payload, verify the input\n")
	}

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
		keyPassword, err := v.GetPassword()
		if err != nil {
			return nil, fmt.Errorf("Unable to get private key password, Decryption failed.")
		}

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

	v.Password, err = oaep.Decrypt(privateKey, ciphertext, []byte(""))
	if err != nil {
		return nil, fmt.Errorf("Decryption failed, use private key with fingerprint: %s", header[2])
	}

	ciphertext, err = base64.StdEncoding.DecodeString(payload[1])
	if err != nil {
		return nil, err
	}

	// decrypt ciphertext using fingerprint as additionalData
	data, err := aead.Decrypt(v.Password, ciphertext, []byte(header[2]))
	if err != nil {
		return nil, err
	}
	return data, nil
}
