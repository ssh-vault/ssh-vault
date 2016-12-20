package sshvault

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kr/pty"
	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

// zomg this is a race condition
func PtyWriteback(pty *os.File, msg string) {
	time.Sleep(500 * time.Millisecond)
	defer pty.Sync()
	pty.Write([]byte(msg))
}

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

	key_pw := string("argle-bargle\n")
	pty, tty, err := pty.Open()
	if err != nil {
		t.Errorf("Unable to open pty: %s", err)
	}

	// File Descriptor magic. GetPasswordPrompt() reads the password
	// from stdin. For the test, we save stdin to a spare FD,
	// point stdin at the file, run the system under test, and
	// finally restore the original stdin
	old_stdin, _ := syscall.Dup(int(syscall.Stdin))
	syscall.Dup2(int(tty.Fd()), int(syscall.Stdin))

	go PtyWriteback(pty, key_pw)

	key_pw_test, err := vault.GetPasswordPrompt()

	syscall.Dup2(old_stdin, int(syscall.Stdin))

	if err != nil {
		t.Error(err)
	}
	if string(strings.Trim(key_pw, "\n")) != string(key_pw_test) {
		t.Errorf("password prompt: expected %s, got %s\n", key_pw, key_pw_test)
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
