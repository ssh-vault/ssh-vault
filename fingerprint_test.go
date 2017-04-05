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

	"github.com/kr/pty"
	"github.com/ssh-vault/crypto"
	"github.com/ssh-vault/crypto/aead"
)

// These are done in one function to avoid declaring global variables in a test
// file.
func TestVaultFunctionsFingerprint(t *testing.T) {
	dir, err := ioutil.TempDir("", "vault")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up

	tmpfile := filepath.Join(dir, "vault")

	vault, err := New("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15", "test_data/id_rsa.pub", "", "create", tmpfile)
	if err != nil {
		t.Error(err)
	}

	keyPw := string("argle-bargle\n")
	pty, tty, err := pty.Open()
	if err != nil {
		t.Errorf("Unable to open pty: %s", err)
	}

	// File Descriptor magic. GetPasswordPrompt() reads the password
	// from stdin. For the test, we save stdin to a spare FD,
	// point stdin at the file, run the system under test, and
	// finally restore the original stdin
	oldStdin, _ := syscall.Dup(int(syscall.Stdin))
	oldStdout, _ := syscall.Dup(int(syscall.Stdout))
	syscall.Dup2(int(tty.Fd()), int(syscall.Stdin))
	syscall.Dup2(int(tty.Fd()), int(syscall.Stdout))

	go PtyWriteback(pty, keyPw)

	keyPwTest, err := vault.GetPasswordPrompt()

	syscall.Dup2(oldStdin, int(syscall.Stdin))
	syscall.Dup2(oldStdout, int(syscall.Stdout))

	if err != nil {
		t.Error(err)
	}
	if string(strings.Trim(keyPw, "\n")) != string(keyPwTest) {
		t.Errorf("password prompt: expected %s, got %s\n", keyPw, keyPwTest)
	}

	PKCS8, err := vault.PKCS8()
	if err != nil {
		t.Error(err)
	}

	vault.PublicKey, err = vault.GetRSAPublicKey(PKCS8)
	if err != nil {
		t.Error(err)
	}

	vault.Fingerprint, err = vault.GenFingerprint(PKCS8)
	if err != nil {
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

func TestVaultFunctionsSTDOUTFingerprint(t *testing.T) {
	dir, err := ioutil.TempDir("", "vault")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up

	vault, err := New("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15", "test_data/id_rsa.pub", "", "create", "")
	if err != nil {
		t.Error(err)
	}

	PKCS8, err := vault.PKCS8()
	if err != nil {
		t.Error(err)
	}

	vault.PublicKey, err = vault.GetRSAPublicKey(PKCS8)
	if err != nil {
		t.Error(err)
	}

	vault.Fingerprint, err = vault.GenFingerprint(PKCS8)
	if err != nil {
		t.Error(err)
	}

	if vault.Password, err = crypto.GenerateNonce(32); err != nil {
		t.Error(err)
	}

	// Skip vault.Create because we don't need/want to interact with an editor
	in := []byte("The quick brown fox jumps over the lazy dog")

	out, err := aead.Encrypt(vault.Password, in, []byte(vault.Fingerprint))
	if err != nil {
		t.Error(err)
	}

	rescueStdout := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	if err = vault.Close(out); err != nil {
		t.Error(err)
	}

	w.Close()
	outStdout, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout
	tmpfile, err := ioutil.TempFile("", "stdout")
	if err != nil {
		t.Error(err)
	}
	tmpfile.Write([]byte(outStdout))
	vault.vault = tmpfile.Name()

	plaintext, err := vault.View()
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(in, plaintext) {
		t.Error("in != out")
	}
}

func TestVaultNewFingerprint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintln(w, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDjjM4JEyg1T8j5YICtqslLNp2UGg80CppTM3ZYu73pEmDhMwbLfdhuI56AQZgWViFsF/7QHDJPcRY2Piu38b4kizTSM0QHEOC7CTo+vnzxptlKLGT1y2mcY1P9VXzCBMSWQN9/vGasgl/sUp1zcTvVT0CjjA6k1dJM6/+aDVtCsFa851VkwbeIsWl5BAHLyL+ur5BX93/BxYnRcYl7ooheuEWWokyWJ0IwEFToPMHAthTbDn1P17wYF43oscTORsFBfkP1JLBKHPDPJCGcBgQButL/srLJf6o44fScAYL99s1dQ/Qqv31aygDmwLdKEDldNnWEaJZ+iidEiIlPtAnLYGnVVA4u+NA2p3egrUrLWmpPjMX6XSb2VRHllzCcY4vZ4F2ud2TFaYG6N+9+vRCdxB+LFcHhm7ottI4vnC5P1bbMagjmFne0+TSKrAfMCw59eiQd8yZVMoE2yPXjFOQt6EOBvB4OHv1AaVt2q0PGqSkv5vIhgsKJWx/6IUj0Kz24hDiMipFb0jL3xstvizAllpC6yF26Ju/nwF03eJJGGxJjrxYd4P5/rY6SWY3yakiUN7pUBgUK2Ok3K3/+BTy5Aag8OXcvOZJumr2X2Wn9DweQeCRjC8UqFDKALqA/3vopZ2S59V4WOg3sV94hEig/KHLISNge1Uatn+qosK2sPw==")
	}))
	defer ts.Close()
	_, err := New("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15", "", ts.URL, "view", "")
	if err != nil {
		t.Error(err)
	}
}
func TestVaultNewFingerprintBadKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintln(w, "ssh-rsa FOO")
	}))
	defer ts.Close()
	_, err := New("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:15", "", ts.URL, "view", "")
	if err == nil {
		t.Error("Expecting error: Use a public ssh key: illegal base64 ...")
	}
}

func TestVaultNewNoKeyFingerprint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
	}))
	defer ts.Close()
	_, err := New("55:cd:f2:7e:4c:0b:e5:a7:6e:6c:fc:6b:8e:58:9d:XX", "", ts.URL, "view", "")
	if err == nil {
		t.Error("Expecting error")
	}
}
