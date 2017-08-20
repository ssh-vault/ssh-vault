package sshvault

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestCacheIsFile(t *testing.T) {
	cache := &cache{}
	if cache.IsFile("/") {
		t.Errorf("Expecting false")
	}
	if !cache.IsFile("cache_test.go") {
		t.Errorf("Expecting true")
	}
}

type mockSchlosser struct{}

func (m mockSchlosser) GetKey(u string) ([]string, error) {
	switch u {
	case "alice":
		return []string{"ssh-rsa ABC"}, nil
	case "bob":
		return nil, nil
	case "matilde":
		return []string{"ssh-rsa ABC", "ssh-rsa ABC", "ssh-rsa ABC"}, nil
	case "pedro":
		return []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrrjZ4Hw9wj/RXaNmwAS0eAxub9LYYCv4bsfxE4UmXcLQSj4YIM8+GfsPkykKZNl5+iatzeKrolYCHLIjC1xwsC199o5lpEBskV1g0uFhRiuguUJxM2r66bbxOfuSZcY9tHD/NkgLg0rTqDzGXtkWbBbjtam9N0H4dbCfgVpGVI8feZqFR5uiukG2eDJKn+0S4UTwZgO7TvSxpMl31xqlPy9EsgEhb+19YYuvSQOXWBX6yuKr1gjY7g3/wmtXRdrZbTjZmIeACITNWgWM7TFEqYf88bHHAMz1pSj5V8Uu0k/yEd2RRIHoMc1fMq5ygMEU6mcEf3C8zy6w5r3rRms2n", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGOhBrPToSBJCblZoK44w3/ub3K6Vx39ilHB/2sJIDqLZTx8I1U2l2RD3WhwKXdqqpH6RZh0piGlWuGV/E7xOseH9qEOKZMgscdvNO9nzD8jkSlShhZQUmhWOqLPcVUDlgIubxrFRVODcFxqgJwjm+qR2X2GaHJottrn5jFhNBEYcjdnuDKXZQ7Cr+K2bOcD+pvhMI7/qtR7jKa7Q5BoRxQEsNQEZvvgJpen2CqAsnjpJXjAXttnXJnAXcyYyOe8ZOCY/tkmXWvn9Fkd1EYmK14rB8WNEe+vraNCS9tSi1PyLMJWr3XNeluLr2/y7gHSyO6xzQNoXiTDDBFW2y3VK5", "ssh-rsa AAA", "ssh-rsa BBB"}, nil
	default:
		return nil, fmt.Errorf("Error")
	}
}

func TestCacheGet(t *testing.T) {
	dir, err := ioutil.TempDir("", "cache")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up
	var testTable = []struct {
		user string
		key  int
		out  string
		err  bool
	}{
		{"alice", 0, "alice.key-1", false},
		{"alice", 1, "alice.key-1", false},
		{"alice", 2, "", true},
		{"bob", 1, "", true},
		{"matilde", 3, "matilde.key-3", false},
		{"matilde", 2, "matilde.key-2", false},
		{"matilde", 0, "matilde.key-1", false},
		{"matilde", 4, "", true},
	}
	cache := &cache{dir}
	gk := mockSchlosser{}
	for _, tt := range testTable {
		out, err := cache.Get(gk, tt.user, "", tt.key)
		if tt.err {
			if err == nil {
				t.Error("Expecting error")
			}
		} else if strings.HasPrefix(out, tt.out) {
			t.Errorf("%q != %q", tt.out, out)
		}
	}
}

func TestCacheGetFingerprint(t *testing.T) {
	dir, err := ioutil.TempDir("", "cacheFingerprint")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir) // clean up
	cache := &cache{dir}
	gk := mockSchlosser{}
	out, err := cache.Get(gk, "pedro", "4a:5e:4b:4d:81:2c:de:db:d5:1d:c3:f9:6e:85:d6:ad", 0)
	if err != nil {
		t.Error(err)
	}
	pubKey, err := ioutil.ReadFile(out)
	expectedKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGOhBrPToSBJCblZoK44w3/ub3K6Vx39ilHB/2sJIDqLZTx8I1U2l2RD3WhwKXdqqpH6RZh0piGlWuGV/E7xOseH9qEOKZMgscdvNO9nzD8jkSlShhZQUmhWOqLPcVUDlgIubxrFRVODcFxqgJwjm+qR2X2GaHJottrn5jFhNBEYcjdnuDKXZQ7Cr+K2bOcD+pvhMI7/qtR7jKa7Q5BoRxQEsNQEZvvgJpen2CqAsnjpJXjAXttnXJnAXcyYyOe8ZOCY/tkmXWvn9Fkd1EYmK14rB8WNEe+vraNCS9tSi1PyLMJWr3XNeluLr2/y7gHSyO6xzQNoXiTDDBFW2y3VK5"
	if string(pubKey) != expectedKey {
		t.Errorf("Expecting %q got %q", expectedKey, pubKey)
	}
}
