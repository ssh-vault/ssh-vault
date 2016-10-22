package sshvault

import (
	"bytes"
	"os"
	"testing"

	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

// These are done in one function to avoid declaring global variables in a test
// file.
func TestVaultFunctions(t *testing.T) {
	vault, err := New("test_data/id_rsa.pub", "", "create", "./test")
	if err != nil {
		t.Error(err.Error())
	}
	defer os.Remove("./test")

	if err = vault.PKCS8(); err != nil {
		t.Error(err.Error())
	}

	if vault.Password, err = crypto.GenerateNonce(32); err != nil {
		t.Error(err.Error())
	}

	// Skip vault.Create because we don't need/want to interact with an editor
	// for tests.
	in := []byte("The quick brown fox jumps over the lazy dog")

	out, err := aead.Encrypt(vault.Password, in, []byte(vault.Fingerprint))
	if err != nil {
		t.Error(err.Error())
	}

	if err = vault.Close(out); err != nil {
		t.Error(err.Error())
	}

	out, err = vault.View()
	if err != nil {
		t.Error(err.Error())
	}

	if !bytes.Equal(in, out) {
		t.Error("in != out")
	}
}
