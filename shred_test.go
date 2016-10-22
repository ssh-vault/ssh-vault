package sshvault

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestShred(t *testing.T) {
	content := []byte("temporary file's content")
	tmpfile, err := ioutil.TempFile("", "shred")
	if err != nil {
		t.Error(err)
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(content); err != nil {
		t.Error(err)
	}

	if err := tmpfile.Close(); err != nil {
		t.Error(err)
	}

	b, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(b, content) {
		t.Error("content != readfile")
	}

	if err := Shred(tmpfile.Name()); err != nil {
		t.Error(err)
	}

	finfo, err := os.Stat(tmpfile.Name())
	if err == nil {
		t.Errorf("Expecting error, finfo: %v", finfo)
	}

}
