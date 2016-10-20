package sshvault

import (
	"crypto/md5"
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

// Cache creates ~/.ssh/vault
func Cache() *cache {
	usr, _ := user.Current()
	sv := filepath.Join(usr.HomeDir, ".ssh", "vault", "keys")
	if _, err := os.Stat(sv); os.IsNotExist(err) {
		os.MkdirAll(sv, os.ModePerm)
	}
	return &cache{sv}
}

// Get return ssh-key
func (c *cache) Get(u string, k int) (string, error) {
	var (
		uKey string
		hash string
	)
	if !isURL.MatchString(u) {
		uKey = fmt.Sprintf("%s/%s.key-%d", c.dir, u, k)
	} else {
		hash = fmt.Sprintf("%x", md5.Sum([]byte(u)))
		uKey = fmt.Sprintf("%s/%s.key-%d", c.dir, hash, k)
	}
	if !c.IsFile(uKey) {
		keys, err := GetKey(u)
		if err != nil {
			return "", err
		}
		if isURL.MatchString(u) {
			u = hash
		}
		for k, v := range keys {
			err = ioutil.WriteFile(fmt.Sprintf("%s/%s.key-%d", c.dir, u, k+1),
				[]byte(v),
				0644)
			if err != nil {
				log.Println(err)
			}
		}
		if !c.IsFile(uKey) {
			return "", fmt.Errorf("key index not found, try -k with a value between 1 and %d", len(keys))
		}
		return uKey, nil
	}
	return uKey, nil
}

// IsFile check if string is a file
func (c *cache) IsFile(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		return false
	}
	if m := f.Mode(); !m.IsDir() && m.IsRegular() && m&400 != 0 {
		return true
	}
	return false
}
