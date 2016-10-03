package sshvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Encrypt AES-256
func Encrypt(key []byte) error {
	bs := 32
	salt := make([]byte, bs-len("Salted__"))
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	return nil
}
