package sshvault

import "os"

//Shred securely delete a file
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

	zeroBytes := make([]byte, fileInfo.Size())

	// fill out the new slice with 0 value
	copy(zeroBytes[:], "0")

	// wipe the content of the target file
	_, err = f.Write([]byte(zeroBytes))
	if err != nil {
		return err
	}

	return f.Close()
}
