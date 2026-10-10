package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestACleanServerChainHasNoFindings(t *testing.T) {
	root := rootCA(t, "Example Root")
	inter := intermediate(t, root, "Example Issuing CA")
	srv := leaf(t, inter, "www.example.org")
	r := audit(t, bundle(srv, inter))
	only(t, r)
	if len(r.Certs) != 2 || r.Certs[0].Role != RoleLeaf || r.Certs[1].Role != RoleCA {
		t.Fatalf("roles: %+v", r.Certs)
	}
}

func TestAChainThatIncludesTheRootIsOnlyANote(t *testing.T) {
	root := rootCA(t, "Example Root")
	inter := intermediate(t, root, "Example Issuing CA")
	srv := leaf(t, inter, "www.example.org")
	only(t, audit(t, bundle(srv, inter, root)), "CW083")
}

// --- validity -----------------------------------------------------------------------------

func TestExpired(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = testNow.AddDate(0, 0, -100), testNow.AddDate(0, 0, -3)
	})
	r := audit(t, bundle(c))
	only(t, r, "CW001")
	if !strings.Contains(find(r, "CW001").Message, "3 days ago") {
		t.Fatal(find(r, "CW001").Message)
	}
}

func TestNotYetValid(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) {
		c.NotBefore, c.NotAfter = testNow.AddDate(0, 0, 5), testNow.AddDate(0, 0, 60)
	})
	only(t, audit(t, bundle(c)), "CW003")
}

func TestExpiringSoonUsesTheThreshold(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.NotAfter = testNow.AddDate(0, 0, 12) })
	only(t, audit(t, bundle(c)), "CW002")
	f := &File{Path: "x"}
	parse(f, bundle(c))
	if got := auditFile(f, Options{Now: testNow, WarnDays: 10}); len(got.Findings) != 0 {
		t.Fatalf("a 10-day threshold should not warn at 12 days: %v", got.Findings)
	}
}

func TestOverlongValidityFollowsTheIssueDate(t *testing.T) {
	root := rootCA(t, "R")
	long := func(from time.Time, days int) []byte {
		return bundle(leaf(t, root, "a.example.org", func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = from, from.AddDate(0, 0, days)
		}))
	}
	// 2026-04 issue: 200 days allowed. Judge at a time inside the validity so only CW030 can fire.
	at := func(b []byte) *Report {
		f := &File{Path: "x"}
		parse(f, b)
		return auditFile(f, Options{Now: f.Certs[0].X.NotBefore.AddDate(0, 0, 1), WarnDays: 1})
	}
	if got := at(long(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), 397)); find(got, "CW030") == nil {
		t.Errorf("397 days from 2026-04 should exceed 200: %v", got.Findings)
	}
	if got := at(long(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), 199)); find(got, "CW030") != nil {
		t.Errorf("199 days from 2026-04 is fine: %v", got.Findings)
	}
	if got := at(long(time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), 397)); find(got, "CW030") != nil {
		t.Errorf("397 days from 2025-04 is within 398: %v", got.Findings)
	}
	if got := at(long(time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), 730)); find(got, "CW030") == nil {
		t.Errorf("two years from 2025-04 exceeds 398: %v", got.Findings)
	}
	if got := at(long(time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC), 800)); find(got, "CW030") != nil {
		t.Errorf("800 days from 2019-04 is within 825: %v", got.Findings)
	}
	// Just past each limit, and just after the 2020 boundary.
	for _, c := range []struct {
		from time.Time
		days int
	}{
		{time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC), 827},
		{time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), 400},
		{time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), 202},
		{time.Date(2020, 9, 10, 0, 0, 0, 0, time.UTC), 500},
	} {
		if got := at(long(c.from, c.days)); find(got, "CW030") == nil {
			t.Errorf("%d days from %s should exceed the limit: %v", c.days, c.from.Format("2006-01-02"), got.Findings)
		}
	}
}

// --- keys and algorithms ------------------------------------------------------------------

func TestWeakRSAKey(t *testing.T) {
	root := rootCA(t, "R")
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skip("this Go refuses to generate 1024-bit RSA keys")
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "weak.example.org"}, DNSNames: []string{"weak.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{"http://ocsp.example.test"},
	}
	c := issue(t, root, tmpl, k)
	r := audit(t, bundle(c))
	only(t, r, "CW010")
	if !strings.Contains(find(r, "CW010").Message, "1024") {
		t.Fatal(find(r, "CW010").Message)
	}
}

func TestA2048BitRSAKeyPasses(t *testing.T) {
	root := rootCA(t, "R")
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example.org"}, DNSNames: []string{"a.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{"http://ocsp.example.test"},
	}
	only(t, audit(t, bundle(issue(t, root, tmpl, k))))
}

func TestObsoleteCurve(t *testing.T) {
	root := rootCA(t, "R")
	c := &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example.org"}, DNSNames: []string{"a.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{"http://ocsp.example.test"},
	}
	only(t, audit(t, bundle(issue(t, root, c, p224(t)))), "CW011")
}

func rsaRoot(t *testing.T, mut ...func(*x509.Certificate)) *authority {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{CommonName: "RSA Root"}, NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{1, 2, 3, 4},
	}
	for _, m := range mut {
		m(tmpl)
	}
	return issue(t, nil, tmpl, rk)
}

func TestSHA1Signature(t *testing.T) {
	root := rsaRoot(t)
	l := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA })
	r := audit(t, bundle(l, root))
	f := find(r, "CW020")
	if f == nil || !strings.Contains(f.Message, "SHA1-RSA") || f.Pos != 1 {
		t.Fatalf("want CW020 on the leaf naming SHA1-RSA: %v", r.Findings)
	}
	if len(r.Findings) != 2 { // CW083 for the included root
		t.Fatalf("a SHA-1 link must not break the chain: %v", r.Findings)
	}
}

// Go will not sign with MD5, so the algorithm OID is swapped in a signed certificate. The signature
// no longer matches, which does not matter for a rule about the algorithm a certificate names.
func TestMD5Signature(t *testing.T) {
	l := leaf(t, rsaRoot(t), "a.example.org")
	sha256OID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	md5OID := []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04}
	if n := bytes.Count(l.cert.Raw, sha256OID); n != 2 {
		t.Fatalf("expected the algorithm OID twice, found %d", n)
	}
	raw := bytes.ReplaceAll(bytes.Clone(l.cert.Raw), sha256OID, md5OID)
	f := find(audit(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), "CW020")
	if f == nil || !strings.Contains(f.Message, "MD5-RSA") {
		t.Fatalf("want CW020 naming MD5-RSA: %v", f)
	}
}

func TestASelfSignedRootWithSHA1IsNotFlagged(t *testing.T) {
	root := rsaRoot(t, func(c *x509.Certificate) { c.SignatureAlgorithm = x509.SHA1WithRSA })
	if root.cert.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatal("the test needs a SHA-1 root")
	}
	only(t, audit(t, bundle(root)))
}

// --- names --------------------------------------------------------------------------------

func TestNoSubjectAlternativeName(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.DNSNames = nil })
	only(t, audit(t, bundle(c)), "CW040")
}

func TestAClientCertificateNeedsNoDNSName(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "alice", func(c *x509.Certificate) {
		c.DNSNames = nil
		c.EmailAddresses = []string{"alice@example.org"}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	only(t, audit(t, bundle(c)))
}

func TestCommonNameNotInSAN(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "old.example.org", func(c *x509.Certificate) { c.DNSNames = []string{"new.example.org"} })
	only(t, audit(t, bundle(c)), "CW041")
}

func TestWildcardCoversTheCommonName(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "www.example.org", func(c *x509.Certificate) { c.DNSNames = []string{"*.example.org"} })
	only(t, audit(t, bundle(c)), "CW043")
}

func TestMalformedWildcard(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.DNSNames = []string{"a.example.org", "a.*.example.org"} })
	only(t, audit(t, bundle(c)), "CW042", "CW043")
}

func TestWildcardsThatAreNotOneLeftmostLabel(t *testing.T) {
	root := rootCA(t, "R")
	for _, name := range []string{"*.*.example.org", "*.org"} {
		c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.DNSNames = []string{"a.example.org", name} })
		if r := audit(t, bundle(c)); find(r, "CW042") == nil {
			t.Errorf("%s: want CW042: %v", name, r.Findings)
		}
	}
}

func TestACommonNameThatIsNotAHostNameIsNotCompared(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "webserver", func(c *x509.Certificate) { c.DNSNames = []string{"www.example.org"} })
	only(t, audit(t, bundle(c)))
}

func TestInternalNamesAndPrivateAddresses(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "db.corp.local", func(c *x509.Certificate) {
		c.DNSNames = []string{"db.corp.local", "intranet"}
		c.IPAddresses = []net.IP{net.ParseIP("10.1.2.3")}
	})
	r := audit(t, bundle(c))
	only(t, r, "CW044")
	n := 0
	for _, f := range r.Findings {
		if f.ID == "CW044" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("want 3 CW044 (two names, one address), got %d: %v", n, r.Findings)
	}
}

// --- usage --------------------------------------------------------------------------------

func TestDNSNamesButNoServerAuth(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
	only(t, audit(t, bundle(c)), "CW050")
}

func TestAnyExtendedKeyUsageCoversServers(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} })
	only(t, audit(t, bundle(c)))
}

func TestKeyEnciphermentIsEnoughForRSAButNotEC(t *testing.T) {
	root := rootCA(t, "R")
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaLeaf := issue(t, root, &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example.org"}, DNSNames: []string{"a.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{"http://ocsp.example.test"},
	}, rk)
	only(t, audit(t, bundle(rsaLeaf)))
	ecLeaf := leaf(t, root, "b.example.org", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment })
	only(t, audit(t, bundle(ecLeaf)), "CW053")
}

func TestNoExtendedKeyUsageIsANote(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.ExtKeyUsage = nil })
	only(t, audit(t, bundle(c)), "CW051")
}

func TestKeyUsageThatCannotHandshake(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign })
	only(t, audit(t, bundle(c)), "CW053")
}

func TestAServerCertificateThatIsAlsoACA(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	})
	r := audit(t, bundle(c))
	only(t, r, "CW052")
	if r.Certs[0].Role != RoleCA {
		t.Fatalf("a CA:TRUE certificate is a CA by role: %+v", r.Certs[0])
	}
}

func TestSelfSignedLeafIsANote(t *testing.T) {
	c := issue(t, nil, &x509.Certificate{
		Subject: pkix.Name{CommonName: "box.example.org"}, DNSNames: []string{"box.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, newKey(t))
	only(t, audit(t, bundle(c)), "CW088")
}

func TestNoRevocationInformationIsANote(t *testing.T) {
	root := rootCA(t, "R")
	c := leaf(t, root, "a.example.org", func(c *x509.Certificate) { c.OCSPServer = nil })
	only(t, audit(t, bundle(c)), "CW064")
}

func TestP384AndP521Pass(t *testing.T) {
	root := rootCA(t, "R")
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c := issue(t, root, &x509.Certificate{
			Subject: pkix.Name{CommonName: "a.example.org"}, DNSNames: []string{"a.example.org"},
			NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			OCSPServer: []string{"http://ocsp.example.test"},
		}, k)
		only(t, audit(t, bundle(c)))
	}
}

// handBuilt is a certificate Go will not create (a DSA key, exponent 3, a short root serial).
// RawIssuer and RawSubject differ unless self is set, so it is not mistaken for self-signed.
func handBuilt(self, ca bool) *x509.Certificate {
	x := &x509.Certificate{Version: 3, SerialNumber: new(big.Int).Lsh(big.NewInt(1), 100), RawIssuer: []byte{1}, RawSubject: []byte{2},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true, IsCA: ca,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: []byte{1}, SubjectKeyId: []byte{2}}
	if self {
		x.RawSubject, x.AuthorityKeyId = x.RawIssuer, nil
	}
	return x
}

func findingsOf(x *x509.Certificate) map[string]string {
	m := map[string]string{}
	for _, f := range checkCert(&Cert{Pos: 1, X: x}, opts()) {
		m[f.ID] = f.Severity
	}
	return m
}

func TestRSAExponentThree(t *testing.T) {
	x := handBuilt(false, false)
	x.PublicKey = &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 3}
	if got := findingsOf(x); got["CW013"] != Warning || got["CW010"] != "" {
		t.Fatalf("%v", got)
	}
}

func TestDSAKey(t *testing.T) {
	x := handBuilt(false, false)
	x.PublicKeyAlgorithm = x509.DSA
	if got := findingsOf(x); got["CW012"] != Error {
		t.Fatalf("%v", got)
	}
}

func TestAShortSerialOnARootIsNotFlagged(t *testing.T) {
	x := handBuilt(true, true)
	x.SerialNumber = big.NewInt(5)
	if got := findingsOf(x); got["CW060"] != "" {
		t.Fatalf("%v", got)
	}
}

func TestACAWithoutSubjectKeyIdentifier(t *testing.T) {
	x := handBuilt(false, true)
	x.SubjectKeyId = nil
	if got := findingsOf(x); got["CW063"] != Info {
		t.Fatalf("%v", got)
	}
}

// --- serial numbers and identifiers (hand-built, because Go will not sign these) ----------

func TestSerialNumbers(t *testing.T) {
	base := func(serial *big.Int) *x509.Certificate {
		return &x509.Certificate{Version: 3, SerialNumber: serial, NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), RawIssuer: []byte{1}, RawSubject: []byte{2},
			BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: []byte{1}}
	}
	cases := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"negative", big.NewInt(-5), "CW061"},
		{"zero", big.NewInt(0), "CW061"},
		{"21 octets", new(big.Int).Lsh(big.NewInt(1), 168), "CW061"},
		{"short", big.NewInt(12345), "CW060"},
		{"63 bits", new(big.Int).Lsh(big.NewInt(1), 62), "CW060"},
		{"64 bits", new(big.Int).Lsh(big.NewInt(1), 63), ""},
		{"160 bits, which needs 21 octets in DER", new(big.Int).Lsh(big.NewInt(1), 159), "CW061"},
		{"20 octets", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1)), ""},
	}
	for _, c := range cases {
		got := checkCert(&Cert{Pos: 1, X: base(c.serial)}, opts())
		found := ""
		for _, f := range got {
			if f.ID == "CW060" || f.ID == "CW061" {
				found = f.ID
			}
		}
		if found != c.want {
			t.Errorf("%s: got %q want %q (%v)", c.name, found, c.want, got)
		}
	}
}

func TestSerialZeroOnARootIsOnlyANote(t *testing.T) {
	// Real roots (Go Daddy Class 2, Hellenic Academic) have serial 0. Trust anchors are not
	// validated for it, so reporting an error would be noise on every system trust store.
	root := &x509.Certificate{Version: 3, SerialNumber: big.NewInt(0), RawIssuer: []byte{1}, RawSubject: []byte{1},
		NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		SubjectKeyId: []byte{1}}
	for _, f := range checkCert(&Cert{Pos: 1, X: root}, opts()) {
		if f.ID == "CW061" && f.Severity != Info {
			t.Fatalf("want info, got %v", f)
		}
	}
}

func TestMissingAuthorityKeyIdentifier(t *testing.T) {
	x := &x509.Certificate{Version: 3, SerialNumber: new(big.Int).Lsh(big.NewInt(1), 100), NotBefore: testNow.AddDate(0, 0, -1),
		NotAfter: testNow.AddDate(0, 0, 60), RawIssuer: []byte{1}, RawSubject: []byte{2},
		BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	found := false
	for _, f := range checkCert(&Cert{Pos: 1, X: x}, opts()) {
		found = found || f.ID == "CW062"
	}
	if !found {
		t.Fatal("want CW062")
	}
}

// --- chains -------------------------------------------------------------------------------

func TestChainOutOfOrder(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I")
	srv := leaf(t, inter, "a.example.org")
	r := audit(t, bundle(srv, root, inter))
	if f := find(r, "CW080"); f == nil || !strings.Contains(f.Message, "#3") {
		t.Fatalf("want CW080 pointing at #3: %v", r.Findings)
	}
}

func TestAGapInTheChainNamesTheMissingIssuer(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "Lost CA", func(c *x509.Certificate) { c.IssuingCertificateURL = []string{"http://ca.example.test/lost.crt"} })
	other := intermediate(t, root, "Other CA")
	srv := leaf(t, inter, "a.example.org")
	r := audit(t, bundle(srv, other))
	only(t, r, "CW081", "CW082")
	if f := find(r, "CW081"); !strings.Contains(f.Message, "Lost CA") && !strings.Contains(f.Message, "issuer") {
		t.Fatal(f.Message)
	}
}

func TestTheAIAAddressIsOfferedWhenTheIssuerIsMissing(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "Lost CA")
	other := intermediate(t, root, "Other CA")
	srv := leaf(t, inter, "a.example.org", func(c *x509.Certificate) { c.IssuingCertificateURL = []string{"http://ca.example.test/lost.crt"} })
	r := audit(t, bundle(srv, other))
	if f := find(r, "CW081"); f == nil || !strings.Contains(f.Message, "http://ca.example.test/lost.crt") {
		t.Fatalf("the leaf's own AIA is where its issuer lives: %v", r.Findings)
	}
}

func TestADuplicate(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I")
	srv := leaf(t, inter, "a.example.org")
	only(t, audit(t, bundle(srv, inter, inter)), "CW084")
}

func TestAChainFileWithNoLeafIsStillAChain(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I")
	only(t, audit(t, bundle(root, inter)), "CW080", "CW083")
}

func TestABundleOfRootsIsNotAChain(t *testing.T) {
	a, b := rootCA(t, "Root A"), rootCA(t, "Root B")
	only(t, audit(t, bundle(a, b)))
}

func TestSeveralLeavesAreNotAChain(t *testing.T) {
	root := rootCA(t, "R")
	only(t, audit(t, bundle(leaf(t, root, "a.example.org"), leaf(t, root, "b.example.org"), root)))
}

func TestAnIssuerThatIsNotACA(t *testing.T) {
	root := rootCA(t, "R")
	notCA := leaf(t, root, "ca.example.org")
	srv := issue(t, notCA, &x509.Certificate{
		Subject: pkix.Name{CommonName: "child.example.org"}, DNSNames: []string{"child.example.org"},
		NotBefore: testNow.AddDate(0, 0, -1), NotAfter: testNow.AddDate(0, 0, 60), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{"http://ocsp.example.test"},
	}, newKey(t))
	r := audit(t, bundle(srv, notCA))
	notMarked := false
	for _, f := range r.Findings {
		notMarked = notMarked || (f.ID == "CW087" && strings.Contains(f.Message, "not marked as a CA"))
	}
	if !notMarked {
		t.Fatalf("want CW087 saying the issuer is not a CA: %v", r.Findings)
	}
}

func TestAnIssuerWithoutKeyCertSign(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })
	srv := leaf(t, inter, "a.example.org")
	r := audit(t, bundle(srv, inter))
	only(t, r, "CW053", "CW087")
}

func TestPathLengthConstraint(t *testing.T) {
	root := rootCA(t, "R", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true })
	inter := intermediate(t, root, "I")
	srv := leaf(t, inter, "a.example.org")
	r := audit(t, bundle(srv, inter, root))
	if f := find(r, "CW087"); f == nil || !strings.Contains(f.Message, "path length") {
		t.Fatalf("want a path length error: %v", r.Findings)
	}
	ok := rootCA(t, "R2", func(c *x509.Certificate) { c.MaxPathLen = 1 })
	i2 := intermediate(t, ok, "I2")
	l2 := leaf(t, i2, "b.example.org")
	if r := audit(t, bundle(l2, i2, ok)); find(r, "CW087") != nil {
		t.Fatalf("one intermediate under pathlen 1 is fine: %v", r.Findings)
	}
}

func TestALeafThatOutlivesItsIssuer(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I", func(c *x509.Certificate) { c.NotAfter = testNow.AddDate(0, 0, 40) })
	srv := leaf(t, inter, "a.example.org")
	only(t, audit(t, bundle(srv, inter)), "CW085")
}

func TestNamesMatchButTheSignatureDoesNot(t *testing.T) {
	root := rootCA(t, "R")
	real := intermediate(t, root, "Same Name", func(c *x509.Certificate) { c.SubjectKeyId = []byte{9, 9, 9, 9} })
	impostor := intermediate(t, root, "Same Name", func(c *x509.Certificate) { c.SubjectKeyId = []byte{9, 9, 9, 9} })
	srv := leaf(t, real, "a.example.org")
	r := audit(t, bundle(srv, impostor))
	if f := find(r, "CW086"); f == nil {
		t.Fatalf("want CW086: %v", r.Findings)
	}
}

// --- loading ------------------------------------------------------------------------------

// privateKeyPEM builds a PEM private key at test time so no key-shaped text sits in the repository.
func privateKeyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestAPrivateKeyInACertificateFile(t *testing.T) {
	root := rootCA(t, "R")
	srv := leaf(t, root, "a.example.org")
	data := append(bundle(srv), privateKeyPEM(t)...)
	r := audit(t, data)
	only(t, r, "CW070")
	if len(r.Certs) != 1 {
		t.Fatalf("the certificate is still read: %d", len(r.Certs))
	}
	if strings.Contains(find(r, "CW070").Message, "MIG") {
		t.Fatal("the key material must never be echoed")
	}
}

func TestAnEncryptedKeyAndAnRSAKeyAreFoundToo(t *testing.T) {
	for _, header := range []string{"ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		data := []byte("-----BEGIN " + header + "-----\n!!!not base64!!!\n-----END " + header + "-----\n")
		r := audit(t, data)
		if find(r, "CW070") == nil {
			t.Errorf("%s not detected: %v", header, r.Findings)
		}
	}
}

func TestDERIsRead(t *testing.T) {
	root := rootCA(t, "R")
	srv := leaf(t, root, "a.example.org")
	r := audit(t, srv.cert.Raw)
	only(t, r)
	if len(r.Certs) != 1 {
		t.Fatal("DER not parsed")
	}
}

func TestGarbageIsReportedNotRead(t *testing.T) {
	for name, data := range map[string][]byte{
		"binary":      {0, 1, 2, 3, 4},
		"empty":       {},
		"text":        []byte("hello"),
		"bad pem":     []byte("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
		"truncated":   []byte("-----BEGIN CERTIFICATE-----\nMIIB"),
		"wrong block": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}),
	} {
		r := audit(t, data)
		if find(r, "CW071") == nil {
			t.Errorf("%s: want CW071, got %v", name, r.Findings)
		}
	}
}

func TestOtherPEMBlocksAreSkipped(t *testing.T) {
	root := rootCA(t, "R")
	srv := leaf(t, root, "a.example.org")
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3}})
	only(t, audit(t, append(csr, bundle(srv)...)))
}

func TestTextAroundTheBlocksIsIgnored(t *testing.T) {
	root := rootCA(t, "R")
	srv := leaf(t, root, "a.example.org")
	data := append([]byte("Bag Attributes\n  friendlyName: x\nsubject=/CN=a.example.org\n"), bundle(srv)...)
	only(t, audit(t, data))
}

func TestTooManyCertificates(t *testing.T) {
	root := rootCA(t, "R")
	one := bundle(root)
	data := bytes.Repeat(one, MaxCertsPerFile+5)
	f := &File{}
	parse(f, data)
	if len(f.Certs) != MaxCertsPerFile {
		t.Fatalf("read %d", len(f.Certs))
	}
	if len(f.Findings) == 0 {
		t.Fatal("the cap should be reported")
	}
}

func TestAnOversizedFileIsNotRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(p, bytes.Repeat([]byte("A"), MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(files[0].Certs) != 0 || len(files[0].Findings) != 1 || !strings.Contains(files[0].Findings[0].Message, "not read") {
		t.Fatalf("%+v", files[0])
	}
}

func TestDirectoryWalk(t *testing.T) {
	dir := t.TempDir()
	root := rootCA(t, "R")
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a.pem", bundle(root))
	write("sub/b.CRT", bundle(root))
	write("sub/notes.txt", []byte("not a certificate"))
	write(".git/c.pem", bundle(root))
	files, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f.Path))
	}
	if fmt.Sprint(names) != "[a.pem b.CRT]" {
		t.Fatalf("files: %v", names)
	}
}

func TestSymlinksAreNotFollowedInADirectoryWalk(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "elsewhere.pem")
	if err := os.WriteFile(target, bundle(rootCA(t, "R")), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "link.pem")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	files, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("followed a symlink: %v", files[0].Path)
	}
}

func TestAMissingPathIsAnError(t *testing.T) {
	if _, err := Load([]string{filepath.Join(t.TempDir(), "nope.pem")}); err == nil {
		t.Fatal("want an error")
	}
}

func TestTrustedCertificateTrailerIsTolerated(t *testing.T) {
	root := rootCA(t, "R")
	der := append(bytes.Clone(root.cert.Raw), 0x30, 0x03, 0x06, 0x01, 0x00)
	data := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: der})
	r := audit(t, data)
	if len(r.Certs) != 1 {
		t.Fatalf("%v", r.Findings)
	}
}

// --- robustness ---------------------------------------------------------------------------

func FuzzParseAndAudit(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file := &File{Path: "fuzz"}
		parse(file, data)
		_ = auditFile(file, opts())
	})
}

func TestMutatedCertificatesNeverPanic(t *testing.T) {
	root := rootCA(t, "R")
	inter := intermediate(t, root, "I")
	srv := leaf(t, inter, "a.example.org")
	data := bundle(srv, inter, root)
	for i := 0; i < len(data); i += 7 {
		m := bytes.Clone(data)
		m[i] ^= 0x55
		file := &File{Path: "m"}
		parse(file, m)
		_ = auditFile(file, opts())
	}
	for cut := 0; cut < len(data); cut += 13 {
		file := &File{Path: "c"}
		parse(file, data[:cut])
		_ = auditFile(file, opts())
	}
}
