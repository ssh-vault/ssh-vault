package sshvault

import "fmt"

// Vault structure
type Vault struct {
	key    string
	user   string
	option string
	vault  string
}

// New initialize vault parameters
func New(k, u, o, v string) error {
	cache := Cache()
	if u != "" {
		path, err := cache.Get(u)
		if err != nil {
			return err
		}
		fmt.Printf("path = %+v\n", path)
	}
	return nil
}
