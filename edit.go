package sshvault

import (
	"io/ioutil"
	"os"
	"os/exec"
)

// Edit opens $EDITOR default to vi
func (v *vault) Edit(data []byte) ([]byte, error) {
	tmpfile, err := ioutil.TempFile("", v.Fingerprint)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())
	err = ioutil.WriteFile(tmpfile.Name(), data, 0600)
	if err != nil {
		return nil, err
	}
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
