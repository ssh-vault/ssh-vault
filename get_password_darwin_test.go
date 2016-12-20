// +build darwin

package sshvault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/keybase/go-keychain"
	"github.com/kr/pty"
)

func InjectKeychainPassword(path, pw string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetLabel(fmt.Sprintf("SSH: %s", path))
	item.SetService("SSH")
	item.SetAccount(path)
	item.SetData([]byte(pw))
	item.SetSynchronizable(keychain.SynchronizableNo)

	return keychain.AddItem(item)
}

func DeleteKeychainPassword(path string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService("SSH")
	item.SetAccount(path)

	return keychain.DeleteItem(item)
}

func TestKeychain(t *testing.T) {
	key_pw := "argle-bargle"
	key_bad_pw := "totally-bogus\n"

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
	key_path, err := filepath.Abs(vault.key)
	if err != nil {
		t.Errorf("Error finding private key: %s", err)
	}
	err = InjectKeychainPassword(key_path, key_pw)
	if err != nil {
		t.Errorf("Error setting up keychain for testing: %s", err)
	}
	defer DeleteKeychainPassword(key_path) // clean up

	_, tty, err := pty.Open()
	if err != nil {
		t.Errorf("Unable to open pty: %s", err)
	}

	// File Descriptor magic. GetPasswordPrompt() reads the password
	// from stdin. For the test, we save stdin to a spare FD,
	// point stdin at the file, run the system under test, and
	// finally restore the original stdin
	old_stdin, _ := syscall.Dup(int(syscall.Stdin))
	old_stdout, _ := syscall.Dup(int(syscall.Stdout))
	syscall.Dup2(int(tty.Fd()), int(syscall.Stdin))
	syscall.Dup2(int(tty.Fd()), int(syscall.Stdout))

	go PtyWriteback(pty, key_bad_pw)

	key_pw_test, err := vault.GetPassword()

	syscall.Dup2(old_stdin, int(syscall.Stdin))
	syscall.Dup2(old_stdout, int(syscall.Stdout))

	if err != nil {
		t.Error(err)
	}
	if strings.Trim(string(key_pw_test), "\n") == strings.Trim(key_bad_pw, "\n") {
		t.Errorf("PTY-based password prompt used, not keychain!")
	}

	if strings.Trim(string(key_pw_test), "\n") != strings.Trim(key_pw, "\n") {
		t.Errorf("keychain error: %s expected %s, got %s\n", key_path, key_pw, key_pw_test)
	}

}
