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
		{"alice", 1, "alice.key-1", false},
		{"alice", 2, "", true},
	}
	cache := &cache{dir}
	gk := mockSchlosser{}
	for _, tt := range testTable {
		out, err := cache.Get(gk, tt.user, tt.key)
		if tt.err {
			if err == nil {
				t.Error("Expecting error")
			}
		} else if strings.HasPrefix(out, tt.out) {
			t.Errorf("%q != %q", tt.out, out)
		}
		//fmt.Printf("out = %+v\n", out)
		//fmt.Printf("err = %+v\n", err)
	}
}
