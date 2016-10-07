package sshvault

import (
	"bytes"
	"os"
	"testing"
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

	if err = vault.GenPassword(); err != nil {
		t.Error(err.Error())
	}

	// Skip vault.Create because we don't need/want to interact with an editor
	// for tests.
	in := []byte("This is a simple test message")

	byt, err := vault.Encrypt(in)
	if err != nil {
		t.Error(err.Error())
	}

	if err = vault.Close(byt); err != nil {
		t.Error(err.Error())
	}

	byt, err = vault.View()
	if err != nil {
		t.Error(err.Error())
	}

	if !bytes.Equal(in, byt) {
		t.Error("in != byt")
	}
}
