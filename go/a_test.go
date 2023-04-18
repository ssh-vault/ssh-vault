package sshvault

import (
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
)

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	_, fn, line, _ := runtime.Caller(1)
	if a != b {
		t.Errorf("Expected: %v (type %v)  Got: %v (type %v)  in %s:%d", a, reflect.TypeOf(a), b, reflect.TypeOf(b), fn, line)
	}
}

// PtyWriteback
func PtyWriteback(pty *os.File, msg string) {
	time.Sleep(500 * time.Millisecond)
	defer pty.Sync()
	pty.Write([]byte(msg))
}
