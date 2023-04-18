package sshvault

import "bytes"

// Encode return base64 string with line break every 64 chars
func (v *vault) Encode(b string, n int) []byte {
	a := []rune(b)
	var buffer bytes.Buffer
	for i, r := range a {
		buffer.WriteRune(r)
		if i > 0 && (i+1)%64 == 0 {
			buffer.WriteRune('\n')
		}
	}
	return buffer.Bytes()
}
