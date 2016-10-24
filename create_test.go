package sshvault

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

func TestCreate(t *testing.T) {
	dir, err := ioutil.TempDir("", "vault")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up

	tmpfile := filepath.Join(dir, "vault")

	vault, err := New("test_data/id_rsa.pub", "", "create", tmpfile)
	if err != nil {
		t.Error(err)
	}

	if err = vault.PKCS8(); err != nil {
		t.Error(err)
	}

	if vault.Password, err = crypto.GenerateNonce(32); err != nil {
		t.Error(err)
	}

	os.Setenv("EDITOR", "cat")

	data, err := vault.Create()
	if err != nil {
		t.Error(err)
	}

	out, err := aead.Encrypt(vault.Password, data, []byte(vault.Fingerprint))
	if err != nil {
		t.Error(err)
	}
	if err = vault.Close(out); err != nil {
		t.Error(err)
	}

	plaintext, err := vault.View()
	if err != nil {
		t.Error(err)
	}

	if len(plaintext) != 0 {
		t.Error("Expecting 0")
	}
}
