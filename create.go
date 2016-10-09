package sshvault

import (
	"io/ioutil"
	"os"
	"os/exec"
)

// Create opens $EDITOR default to vi
func (v *vault) Create() ([]byte, error) {
	tmpfile, err := ioutil.TempFile("", v.Fingerprint)
	if err != nil {
		return nil, err
	}
	defer Shred(tmpfile.Name())
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, tmpfile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		return nil, err
	}
	return b, nil
}
