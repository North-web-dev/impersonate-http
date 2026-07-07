package main

import "testing"

func TestKeystoreDailyQuota(t *testing.T) {
	ks := &keystore{keys: map[string]*keyState{
		"k": newKeyState(keyConfig{Key: "k", Name: "acme", Daily: 2}),
	}}
	st, ok := ks.lookup("k")
	if !ok {
		t.Fatal("key not found")
	}
	for i := 0; i < 2; i++ {
		if ok, _ := st.admit(); !ok {
			t.Fatalf("request %d should be admitted", i+1)
		}
	}
	if ok, reason := st.admit(); ok || reason != "daily quota exceeded" {
		t.Fatalf("3rd request: ok=%v reason=%q, want quota block", ok, reason)
	}
	if u := st.usage(); u["used_today"].(int64) != 2 {
		t.Errorf("used_today = %v, want 2", u["used_today"])
	}
}

func TestKeystoreRateLimit(t *testing.T) {
	st := newKeyState(keyConfig{Key: "k", RPS: 1, Burst: 1})
	if ok, _ := st.admit(); !ok {
		t.Fatal("first request within burst should pass")
	}
	if ok, reason := st.admit(); ok || reason != "rate limit exceeded" {
		t.Fatalf("burst exhausted: ok=%v reason=%q, want rate block", ok, reason)
	}
}

func TestUnknownKey(t *testing.T) {
	ks := &keystore{keys: map[string]*keyState{}}
	if _, ok := ks.lookup("nope"); ok {
		t.Error("unknown key should not resolve")
	}
	var nilKS *keystore
	if _, ok := nilKS.lookup("x"); ok {
		t.Error("nil keystore should never resolve")
	}
}
