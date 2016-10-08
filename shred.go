package sshvault

import (
	"fmt"
	"os"
)

func Shred(file string) error {
	fmt.Printf("file = %+v\n", file)
	f, err := os.OpenFile(file, os.O_RDWR, 0600)

	if err != nil {
		panic(err.Error())
	}

	defer f.Close()

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

	return os.Remove(file)
}
