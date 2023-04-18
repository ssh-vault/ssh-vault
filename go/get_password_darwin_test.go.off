// +build darwin
// +build amd64

package sshvault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/kr/pty"
	"github.com/ssh-vault/go-keychain"
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
	keyPw := "argle-bargle"
	keyBadPw := "totally-bogus\n"

	dir, err := ioutil.TempDir("", "vault")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up

	tmpfile := filepath.Join(dir, "vault")

	vault, err := New("", "test_data/id_rsa.pub", "", "create", tmpfile)
	if err != nil {
		t.Error(err)
	}
	keyPath, err := filepath.Abs(vault.key)
	if err != nil {
		t.Errorf("Error finding private key: %s", err)
	}
	err = InjectKeychainPassword(keyPath, keyPw)
	if err != nil {
		t.Errorf("Error setting up keychain for testing: %s", err)
	}
	defer DeleteKeychainPassword(keyPath) // clean up

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

	go PtyWriteback(pty, keyBadPw)

	keyPwTest, err := vault.GetPassword()

	syscall.Dup2(oldStdin, int(syscall.Stdin))
	syscall.Dup2(oldStdout, int(syscall.Stdout))

	if err != nil {
		t.Error(err)
	}
	if strings.Trim(string(keyPwTest), "\n") == strings.Trim(keyBadPw, "\n") {
		t.Errorf("PTY-based password prompt used, not keychain!")
	}

	if strings.Trim(string(keyPwTest), "\n") != strings.Trim(keyPw, "\n") {
		t.Errorf("keychain error: %s expected %s, got %s\n", keyPath, keyPw, keyPwTest)
	}

}
