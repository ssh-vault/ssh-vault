package sshvault

import "testing"

func TestCacheIsFile(t *testing.T) {
	cache := &cache{}
	if cache.IsFile("/") {
		t.Errorf("Expecting false")
	}
	if !cache.IsFile("cache_test.go") {
		t.Errorf("Expecting true")
	}
}
