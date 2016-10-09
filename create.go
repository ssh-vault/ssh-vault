package sshvault

import (
	"bufio"
	"io/ioutil"
	"os"
	"os/exec"
)

// Create reads from STDIN or opens $EDITOR default to vi
func (v *vault) Create() ([]byte, error) {
	// check if there is someting to read on STDIN
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Split(bufio.ScanBytes)
		var stdin []byte
		for scanner.Scan() {
			stdin = append(stdin, scanner.Bytes()...)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return stdin, nil
	}

	// use $EDITOR
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
