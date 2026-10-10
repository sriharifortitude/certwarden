// Command mkfixtures writes the certificate files in testdata/ that the README's example runs on.
//
// Every certificate is made for this purpose, under invented names, with fresh random keys; the
// private keys are discarded and never written. Because the keys are random the files differ on
// every run, so they are committed and CI does not regenerate them. The README's example judges
// them at a fixed time (--now), which is what keeps its output stable.
//
// Run from the repository root:  go run ./scripts/mkfixtures testdata
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// now is the moment the fixtures are designed to be judged at.
var now = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

type authority struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkfixtures:", err)
		os.Exit(1)
	}
	return v
}

func serial() *big.Int {
	n := must(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)))
	return n.Add(n, new(big.Int).Lsh(big.NewInt(1), 100))
}

func ecKey() crypto.Signer { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }

func issue(parent *authority, t *x509.Certificate, key crypto.Signer) *authority {
	t.SerialNumber = serial()
	signer, pc := key, t
	if parent != nil {
		signer, pc = parent.key, parent.cert
	}
	der := must(x509.CreateCertificate(rand.Reader, t, pc, key.Public(), signer))
	return &authority{cert: must(x509.ParseCertificate(der)), key: key}
}

func ca(parent *authority, name string, years int, aia string) *authority {
	t := &x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{"Example Trust (fixture)"}},
		NotBefore: now.AddDate(-years, 0, 0), NotAfter: now.AddDate(years, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if aia != "" {
		t.IssuingCertificateURL = []string{aia}
	}
	return issue(parent, t, ecKey())
}

func leaf(parent *authority, cn string, mut func(*x509.Certificate), key crypto.Signer) *authority {
	t := &x509.Certificate{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: now.AddDate(0, 0, -30), NotAfter: now.AddDate(0, 0, 60),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: []string{"http://ocsp.example.org"},
	}
	if mut != nil {
		mut(t)
	}
	if key == nil {
		key = ecKey()
	}
	return issue(parent, t, key)
}

func write(dir, name string, auths ...*authority) {
	var data []byte
	for _, a := range auths {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})...)
	}
	must(0, os.WriteFile(filepath.Join(dir, name), data, 0o644))
}

func main() {
	dir := "testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	must(0, os.MkdirAll(dir, 0o755))

	root := ca(nil, "Example Trust Root", 20, "")
	issuing := ca(root, "Example Trust Issuing CA", 8, "http://ca.example.org/issuing.crt")
	other := ca(root, "Example Trust Other CA", 8, "")

	write(dir, "fullchain.pem", leaf(issuing, "www.example.org", nil, nil), issuing)

	write(dir, "expired.pem", leaf(issuing, "old.example.org", func(t *x509.Certificate) {
		t.NotBefore, t.NotAfter = now.AddDate(0, 0, -120), now.AddDate(0, 0, -21)
	}, nil), issuing)

	write(dir, "no-san.pem", leaf(issuing, "legacy.example.org", func(t *x509.Certificate) { t.DNSNames = nil }, nil), issuing)

	srv := leaf(issuing, "www.example.org", nil, nil)
	write(dir, "wrong-order.pem", srv, root, issuing)

	write(dir, "missing-intermediate.pem",
		leaf(issuing, "api.example.org", func(t *x509.Certificate) {
			t.IssuingCertificateURL = []string{"http://ca.example.org/issuing.crt"}
		}, nil), other)

	weak := must(rsa.GenerateKey(rand.Reader, 1024))
	write(dir, "weak.pem", leaf(issuing, "weak.example.org", func(t *x509.Certificate) {
		t.KeyUsage |= x509.KeyUsageKeyEncipherment
	}, weak))

	write(dir, "root.pem", root)
}
