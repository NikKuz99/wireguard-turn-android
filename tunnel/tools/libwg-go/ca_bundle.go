package main

import (
	"crypto/x509"
	_ "embed"
	"log"
	"os"
)

//go:embed certs/cacert.pem
var mozillaCABundlePEM []byte

// loadCABundle returns a *x509.CertPool for TLS verification.
// Priority: SSL_CERT_FILE env → system pool → embedded Mozilla bundle.
// On Android the system pool is often empty, so the embedded bundle
// (containing HARICA TLS RSA Root CA 2021) is essential.
func loadCABundle() *x509.CertPool {
	if file := os.Getenv("SSL_CERT_FILE"); file != "" {
		if data, err := os.ReadFile(file); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(data) {
				return pool
			}
		}
	}
	if sys, err := x509.SystemCertPool(); err == nil && sys != nil && len(sys.Subjects()) > 0 {
		return sys
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mozillaCABundlePEM) {
		log.Println("CA bundle: failed to parse embedded Mozilla bundle")
	}
	return pool
}
