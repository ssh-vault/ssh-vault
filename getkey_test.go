package sshvault

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetKeyFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintln(w, "ssh-rsa ABC")
	}))
	defer ts.Close()

	l := Locksmith{}
	s, err := l.GetKey(ts.URL)
	if err != nil {
		t.Error(err)
	}
	expect(t, 1, len(s))
}

func TestGetKeyNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
	}))
	defer ts.Close()

	l := Locksmith{}
	s, err := l.GetKey(ts.URL)
	if err == nil {
		t.Errorf("Expecting error")
	}
	expect(t, 0, len(s))
}

func TestGetKeyMultipleKeys(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintf(w, "%s\n%s\n%s\n%s\n%s\n\n\n",
			"ssh-rsa ABC",
			"no key",
			"ssh-rsa ABC",
			"ssh-foo ABC",
			"ssh-rsa end",
		)
	}))
	defer ts.Close()

	l := Locksmith{}
	s, err := l.GetKey(ts.URL)
	if err != nil {
		t.Error(err)
	}
	expect(t, 3, len(s))
}
