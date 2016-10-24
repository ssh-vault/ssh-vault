package sshvault

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

// These are done in one function to avoid declaring global variables in a test
// file.
func TestVaultFunctions(t *testing.T) {
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

	enc1, err := ioutil.ReadFile(tmpfile)
	if err != nil {
		t.Error(err)
	}

	plaintext, err := vault.View()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(in, plaintext) {
		t.Error("in != out")
	}

	os.Setenv("EDITOR", "cat")
	edited, err := vault.Edit(plaintext)
	if err != nil {
		t.Error(err)
	}

	out, err = aead.Encrypt(vault.Password, edited, []byte(vault.Fingerprint))
	if err != nil {
		t.Error(err)
	}

	if err = vault.Close(out); err != nil {
		t.Error(err)
	}

	plaintext, err = vault.View()
	if err != nil {
		t.Error(err)
	}

	enc2, err := ioutil.ReadFile(tmpfile)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(edited, plaintext) {
		t.Error("edited != plaintext ")
	}

	if bytes.Equal(enc1, enc2) {
		t.Error("Expecting different encrypted outputs")
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
