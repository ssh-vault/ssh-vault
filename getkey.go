package sshvault

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strings"
)

// Schlosser interface
type Schlosser interface {
	GetKey(string) ([]string, error)
}

// Locksmith implements Schlosser
type Locksmith struct {
	Github string
}

// GetKey fetches ssh-key from url
func (l Locksmith) GetKey(u string) ([]string, error) {
	url := u
	if !isURL.MatchString(u) {
		url = fmt.Sprintf("%s/%s.keys", l.Github, u)
	}
	client := &http.Client{}
	// create a new request
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ssh-vault")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	reader := bufio.NewReader(res.Body)
	tp := textproto.NewReader(reader)
	keys := []string{}
	for {
		if line, err := tp.ReadLine(); err != nil {
			if err == io.EOF {
				if len(keys) == 0 {
					return nil, fmt.Errorf("key %q not found", u)
				}
				return keys, nil
			}
			return nil, err
		} else if strings.HasPrefix(line, "ssh-rsa") {
			keys = append(keys, line)
		}
	}
}
