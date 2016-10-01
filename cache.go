package sshvault

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
)

type cache struct {
	dir string
}

// Cache creates ~/.ssh-vault
func Cache() *cache {
	usr, _ := user.Current()
	sv := filepath.Join(usr.HomeDir, ".ssh-vault", "keys")
	if _, err := os.Stat(sv); os.IsNotExist(err) {
		os.MkdirAll(sv, os.ModePerm)
	}
	return &cache{sv}
}

// Get return ssh-key
func (c *cache) Get(u string) (string, error) {
	keyPath := fmt.Sprintf("%s/%s.key", c.dir, u)
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		key, err := GetKey(u)
		if err != nil {
			return "", err
		}
		err = ioutil.WriteFile(keyPath, []byte(key), 0644)
		if err != nil {
			log.Println(err)
		}
		return key, nil
	}
	return string(key), err
}
