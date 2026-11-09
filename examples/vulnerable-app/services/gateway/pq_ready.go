package main

import "crypto/tls"

// Hybrid post-quantum key exchange (Go 1.24+).
func pqTLS() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}
