package sshvault

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		t.Error(err)
	}
	defer os.Remove("./test")

	if err = vault.PKCS8(); err != nil {
		t.Error(err)
	}

	if vault.Password, err = crypto.GenerateNonce(32); err != nil {
		t.Error(err)
	}

	// Skip vault.Create because we don't need/want to interact with an editor
	// for tests.
	in := []byte("The quick brown fox jumps over the lazy dog")

	out, err := aead.Encrypt(vault.Password, in, []byte(vault.Fingerprint))
	if err != nil {
		t.Error(err)
	}

	if err = vault.Close(out); err != nil {
		t.Error(err)
	}

	out, err = vault.View()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(in, out) {
		t.Error("in != out")
	}
}

func TestVaultNew(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintln(w, "ssh-rsa ABC")
	}))
	defer ts.Close()
	_, err := New("", ts.URL, "view", "")
	if err != nil {
		t.Error(err)
	}
}

func TestVaultNewNoKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
	}))
	defer ts.Close()
	_, err := New("", ts.URL, "view", "")
	if err == nil {
		t.Error("Expecting error")
	}
}
