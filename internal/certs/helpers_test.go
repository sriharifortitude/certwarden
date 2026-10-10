package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testNow is the clock every test judges certificates at.
var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func opts() Options { return Options{Now: testNow, WarnDays: 30} }

// authority is a certificate with the key that can sign for it.
type authority struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func p224(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, new(big.Int).Lsh(big.NewInt(1), 100))
}

// issue signs tmpl with parent (or itself when parent is nil) and returns the parsed result.
func issue(t *testing.T, parent *authority, tmpl *x509.Certificate, key crypto.Signer) *authority {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = serial(t)
	}
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatalf("create %q: %v", tmpl.Subject.CommonName, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{cert: c, key: key}
}

func rootCA(t *testing.T, name string, mut ...func(*x509.Certificate)) *authority {
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             testNow.AddDate(-5, 0, 0),
		NotAfter:              testNow.AddDate(15, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	for _, m := range mut {
		m(tmpl)
	}
	return issue(t, nil, tmpl, newKey(t))
}

func intermediate(t *testing.T, parent *authority, name string, mut ...func(*x509.Certificate)) *authority {
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             testNow.AddDate(-2, 0, 0),
		NotAfter:              testNow.AddDate(8, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	for _, m := range mut {
		m(tmpl)
	}
	return issue(t, parent, tmpl, newKey(t))
}

func leaf(t *testing.T, parent *authority, name string, mut ...func(*x509.Certificate)) *authority {
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             testNow.AddDate(0, 0, -10),
		NotAfter:              testNow.AddDate(0, 0, 80),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:            []string{"http://ocsp.example.test"},
	}
	for _, m := range mut {
		m(tmpl)
	}
	return issue(t, parent, tmpl, newKey(t))
}

// bundle writes certificates as one PEM file's contents, in the order given.
func bundle(auths ...*authority) []byte {
	var out []byte
	for _, a := range auths {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})...)
	}
	return out
}

// audit parses data as a file and audits it.
func audit(t *testing.T, data []byte) *Report {
	t.Helper()
	f := &File{Path: "test.pem"}
	parse(f, data)
	return auditFile(f, opts())
}

func ids(r *Report) map[string]bool {
	m := map[string]bool{}
	for _, f := range r.Findings {
		m[f.ID] = true
	}
	return m
}

func only(t *testing.T, r *Report, want ...string) {
	t.Helper()
	got := ids(r)
	w := map[string]bool{}
	for _, id := range want {
		w[id] = true
		if !got[id] {
			t.Errorf("missing %s; findings: %v", id, r.Findings)
		}
	}
	for id := range got {
		if !w[id] {
			t.Errorf("unexpected %s; findings: %v", id, r.Findings)
		}
	}
}

func find(r *Report, id string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}
