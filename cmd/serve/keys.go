package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyConfig is one API key's plan, loaded from the keys file.
type keyConfig struct {
	Key   string  `json:"key"`
	Name  string  `json:"name"`
	RPS   float64 `json:"rps"`   // sustained requests/sec (0 = unlimited)
	Burst int     `json:"burst"` // burst size (default: RPS rounded up, min 1)
	Daily int64   `json:"daily"` // requests/day, resets at UTC midnight (0 = unlimited)
}

type keyState struct {
	cfg     keyConfig
	limiter *rate.Limiter // nil when RPS == 0

	mu   sync.Mutex
	day  string
	used int64
}

func newKeyState(c keyConfig) *keyState {
	var lim *rate.Limiter
	if c.RPS > 0 {
		burst := c.Burst
		if burst <= 0 {
			if burst = int(c.RPS); burst < 1 {
				burst = 1
			}
		}
		lim = rate.NewLimiter(rate.Limit(c.RPS), burst)
	}
	return &keyState{cfg: c, limiter: lim, day: utcDay()}
}

// admit charges one request against the key's rate limit and daily quota. The
// reason is non-empty (and admitted false) when a limit is hit.
func (k *keyState) admit() (bool, string) {
	if k.limiter != nil && !k.limiter.Allow() {
		return false, "rate limit exceeded"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if d := utcDay(); d != k.day {
		k.day, k.used = d, 0
	}
	if k.cfg.Daily > 0 && k.used >= k.cfg.Daily {
		return false, "daily quota exceeded"
	}
	k.used++
	return true, ""
}

func (k *keyState) usage() map[string]any {
	k.mu.Lock()
	defer k.mu.Unlock()
	if d := utcDay(); d != k.day {
		k.day, k.used = d, 0
	}
	return map[string]any{
		"name":        k.cfg.Name,
		"used_today":  k.used,
		"daily_limit": k.cfg.Daily,
		"rps":         k.cfg.RPS,
	}
}

func utcDay() string { return time.Now().UTC().Format("2006-01-02") }

// keystore resolves API keys to their state. A nil keystore means auth is off.
type keystore struct {
	keys map[string]*keyState
}

func (ks *keystore) lookup(key string) (*keyState, bool) {
	if ks == nil {
		return nil, false
	}
	s, ok := ks.keys[key]
	return s, ok
}

func loadKeystore(path string) (*keystore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfgs []keyConfig
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return nil, err
	}
	ks := &keystore{keys: make(map[string]*keyState, len(cfgs))}
	for _, c := range cfgs {
		ks.keys[c.Key] = newKeyState(c)
	}
	return ks, nil
}

// singleKeystore wraps one unlimited key (the -key flag).
func singleKeystore(key string) *keystore {
	return &keystore{keys: map[string]*keyState{key: newKeyState(keyConfig{Key: key, Name: "default"})}}
}
