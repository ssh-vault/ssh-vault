package sshvault

import (
	"bufio"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
)

const GITHUB = "https://github.com"

// GetKey fetches ssh-key from url
func GetKey(u string) (string, error) {
	client := &http.Client{}
	// create a new request
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s.keys",
		GITHUB,
		u),
		nil)
	req.Header.Set("User-Agent", "ssh-vault")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	reader := bufio.NewReader(res.Body)
	tp := textproto.NewReader(reader)
	for {
		if line, err := tp.ReadLine(); err != nil {
			return "", err
		} else if strings.HasPrefix(line, "ssh-rsa") {
			return line, nil
		}
	}
}
