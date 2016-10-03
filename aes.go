package sshvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// GenerateNonce creates a new random nonce.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

// Encrypt AES-256 GCM
func (v *vault) Encrypt(message []byte) ([]byte, error) {
	bs := 32
	if len(v.password) != bs {
		return nil, fmt.Errorf("key size != 32, size: %d", len(v.password))
	}
	c, err := aes.NewCipher(v.password)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce, err := GenerateNonce(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, message, nil)
	return out, nil
}

// Decrypt
func (v *vault) Decrypt(message []byte) ([]byte, error) {
	c, err := aes.NewCipher(v.password)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, message[:gcm.NonceSize()])

	out, err := gcm.Open(nil, nonce, message[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}
