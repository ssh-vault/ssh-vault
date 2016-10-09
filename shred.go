package sshvault

import "os"

func Shred(file string) error {
	defer os.Remove(file)

	f, err := os.OpenFile(file, os.O_RDWR, 0600)
	if err != nil {
		return err
	}

	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}

	var size int64 = fileInfo.Size()
	zeroBytes := make([]byte, size)

	// fill out the new slice with 0 value
	copy(zeroBytes[:], "0")

	// wipe the content of the target file
	_, err = f.Write([]byte(zeroBytes))
	if err != nil {
		return err
	}

	f.Close()
}
