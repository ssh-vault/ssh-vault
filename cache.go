package sshvault

import (
	"crypto/md5"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ssh-vault/ssh2pem"
)

type cache struct {
	dir string
}

// Cache creates ~/.ssh/vault
func Cache() *cache {
	d := os.Getenv("SSH_VAULT_CACHE_DIR")
	if d == "" {
		home := os.Getenv("HOME")
		if home == "" {
			usr, _ := user.Current()
			home = usr.HomeDir
		}
		d = filepath.Join(home, ".ssh", "vault", "keys")
	}
	if _, err := os.Stat(d); os.IsNotExist(err) {
		if err := os.MkdirAll(d, os.ModePerm); err != nil {
			log.Fatal(err)
		}
	}
	return &cache{d}
}

// Get return ssh-key
func (c *cache) Get(s Schlosser, u, f string, k int) (string, error) {
	if k == 0 {
		k = 1
	}

	// storage format
	// ~/.ssh/vault/keys/user.key-N
	// or
	// ~/.ssh/vault/keys/<md5>.key-N
	var (
		uKey string
		hash string
	)

	if !isURL.MatchString(u) {
		uKey = fmt.Sprintf("%s/%s.%d", c.dir, u, k)
	} else {
		hash = fmt.Sprintf("%x", md5.Sum([]byte(u)))
		uKey = fmt.Sprintf("%s/%s.%d", c.dir, hash, k)
	}

	// if key not found, fetch it
	if !c.IsFile(uKey) || u == "new" {
		keys, err := s.GetKey(u)
		if err != nil {
			return "", err
		}
		if isURL.MatchString(u) {
			u = hash
		}
		for k, v := range keys {
			err = ioutil.WriteFile(fmt.Sprintf("%s/%s.%d", c.dir, u, k+1),
				[]byte(v),
				0644)
			if err != nil {
				log.Println(err)
			}
		}
		if !c.IsFile(uKey) {
			return "", fmt.Errorf("key index not found, try -k with a value between 1 and %d", len(keys))
		}
	}

	// if fingerprint, find the key that matches
	if f != "" {
		key, err := c.FindFingerprint(uKey, f)
		if err != nil {
			return "", err
		}
		return key, nil
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

// Find searches for key
func (c *cache) FindFingerprint(u, f string) (string, error) {
	files, err := ioutil.ReadDir(c.dir)
	if err != nil {
		return "", err
	}
	var user = strings.TrimSuffix(filepath.Base(u), filepath.Ext(filepath.Base(u)))
	for _, file := range files {
		if strings.HasPrefix(file.Name(), user) {
			out, err := ssh2pem.GetPem(filepath.Join(c.dir, file.Name()))
			if err != nil {
				return "", err
			}
			p, _ := pem.Decode(out)
			x := &vault{}
			fingerprint, _ := x.GenFingerprint(p)
			if f == fingerprint {
				return filepath.Join(c.dir, file.Name()), nil
			}
		}
	}
	return "", fmt.Errorf("key fingerprint: %q not found", f)
}
