package sshvault

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetKeyFoundURL(t *testing.T) {
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

func TestGetKeyFoundUser(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintln(w, "ssh-rsa ABC")
	}))
	defer ts.Close()

	l := Locksmith{ts.URL}
	s, err := l.GetKey("bob")
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

func TestGetKeyRSA(t *testing.T) {
	var privateKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC7NrA42dae4ThIwCAx8IB0Cte09rQhdZ+r3T2uMZm0INdgJKhO
pMg0Wv9VcPKDE+4Aw8N8dL4TqbDN4Lk3fWyGgoMLXahRDmoMKe6o/kFyqHVxlxWe
7Uhe3BHO9XCyuQu51tGzLADNSnVxDb4hhxd4Xjpb4TT69h5djYOLldYelQIDAQAB
AoGAW+TvQSikcZ5pi0RLSVgdJVjBIwHJz3a2Jp1VjnCoWsOYFIhJ2TiHUTOti5oC
YBbjR5rQFQIU3v/3WkdJgxRctR3kKDaEcWo3TTpOk5azIDc9G4XApvtVsWKgAbRh
+VXW1+uWzgHSr5RiQoXrwPP58mVHkxjFQQJjTo2/dDonu00CQQDGvomsOrXWfEh8
13NQfoP/g9q1nK1ZProB8TsNgHZz8l3URmyOb1cpUJkp3seLRnNpwda7ugm0NlQb
Z/lsBrHbAkEA8SXCmdPZ05jPOeyow8aFoLJZahwDOKCFeKOUSvhQpNDtiK+RQZu7
YxvcCOgbNJLTKP5exTOwQGptwWqyf+p0TwJAEa4FhUK7xlbMA/8OjQyUJXjPTfSg
Hx5LYbzZ6fuRjgLzgdy573nMISrAVU8yJRuhTLknpw+HqXZjyQRY1dlKnQJBAIku
c+/SZp5K1cgb6z3EF4x9KQSF/wcduhAQ7nFfpXC9MgOJ7NYn44fT925Rq/hSdjFh
00PXzbI3WUyoh/bgx10CQQCUnAyGmBU11KFVhUYdot6Paq/wrDnIgrzzXhnjtSjS
CagNNGE7cz7xEWLO/jk7ZwB7+wvIPb9BBKXH8/UnVSpJ
-----END RSA PRIVATE KEY-----`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expect(t, "ssh-vault", r.Header.Get("User-agent"))
		fmt.Fprintf(w, "%s", privateKey)
	}))
	defer ts.Close()

	l := Locksmith{}
	s, err := l.GetKey(ts.URL)
	if err != nil {
		t.Error(err)
	}
	expect(t, 1, len(s))
	expect(t, s[0], privateKey)
}
