package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Severities.
const (
	Error   = "error"
	Warning = "warning"
	Info    = "info"
)

// Finding is one thing wrong, or worth knowing, about a file or a certificate.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Pos is the certificate's 1-based position in its file; 0 for a file-level finding.
	Pos     int    `json:"pos,omitempty"`
	Message string `json:"message"`
}

// Options control the audit.
type Options struct {
	// Now is the moment certificates are judged at.
	Now time.Time
	// WarnDays warns about certificates that expire within this many days.
	WarnDays int
}

// Role says what a certificate is for.
type Role string

// Roles.
const (
	RoleLeaf Role = "leaf"
	RoleCA   Role = "CA"
	RoleRoot Role = "root"
)

// Summary describes one certificate for the report.
type Summary struct {
	Pos         int       `json:"pos"`
	Role        Role      `json:"role"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Key         string    `json:"key"`
	Signature   string    `json:"signature"`
	SHA256      string    `json:"sha256"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	DaysLeft    int       `json:"days_left"`
	SelfSigned  bool      `json:"self_signed"`
	Fingerprint string    `json:"-"`
}

// Report is the audit of one file.
type Report struct {
	Path     string    `json:"path"`
	Certs    []Summary `json:"certificates"`
	Findings []Finding `json:"findings"`
}

// Count returns the number of findings of a severity.
func (r *Report) Count(sev string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// Audit checks every file.
func Audit(files []*File, opt Options) []*Report {
	if opt.WarnDays == 0 {
		opt.WarnDays = 30
	}
	out := make([]*Report, 0, len(files))
	for _, f := range files {
		out = append(out, auditFile(f, opt))
	}
	return out
}

func auditFile(f *File, opt Options) *Report {
	r := &Report{Path: f.Path, Certs: []Summary{}, Findings: append([]Finding{}, f.Findings...)}
	for _, c := range f.Certs {
		r.Certs = append(r.Certs, summarise(c, opt))
		r.Findings = append(r.Findings, checkCert(c, opt)...)
	}
	r.Findings = append(r.Findings, checkChain(f)...)
	order := map[string]int{Error: 0, Warning: 1, Info: 2}
	sortFindings(r.Findings, order)
	return r
}

func sortFindings(fs []Finding, order map[string]int) {
	// insertion sort keeps the original order among equals and the inputs are small
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && less(fs[j], fs[j-1], order); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func less(a, b Finding, order map[string]int) bool {
	if order[a.Severity] != order[b.Severity] {
		return order[a.Severity] < order[b.Severity]
	}
	if a.Pos != b.Pos {
		return a.Pos < b.Pos
	}
	return a.ID < b.ID
}

func label(c *x509.Certificate) string {
	if cn := c.Subject.CommonName; cn != "" {
		return cn
	}
	if s := c.Subject.String(); s != "" {
		return s
	}
	return "(empty subject)"
}

func issuerLabel(c *x509.Certificate) string {
	if cn := c.Issuer.CommonName; cn != "" {
		return cn
	}
	if s := c.Issuer.String(); s != "" {
		return s
	}
	return "(empty issuer)"
}

func isCA(c *x509.Certificate) bool { return c.BasicConstraintsValid && c.IsCA }

func roleOf(c *x509.Certificate) Role {
	switch {
	case isCA(c) && selfSigned(c):
		return RoleRoot
	case isCA(c):
		return RoleCA
	case c.Version < 3 && selfSigned(c):
		return RoleRoot // a v1 root has no extensions to say so
	default:
		return RoleLeaf
	}
}

// signedBy reports whether child names parent as its issuer and parent's key makes child's signature.
// linked is true when the names (and key identifiers) match; verified when the signature also checks.
// A signature algorithm Go refuses to verify (MD5, MD2) is treated as verified: the weak-algorithm
// finding reports it, and the chain should not fall apart because of it.
func signedBy(child, parent *x509.Certificate) (linked, verified bool) {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false, false
	}
	if len(child.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 && !bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId) {
		return false, false
	}
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	if err == nil {
		return true, true
	}
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) || errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return true, true
	}
	return true, false
}

func selfSigned(c *x509.Certificate) bool {
	linked, ok := signedBy(c, c)
	return linked && ok
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func keyString(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "EC " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

func summarise(c *Cert, opt Options) Summary {
	x := c.X
	s := Summary{
		Pos: c.Pos, Role: roleOf(x), Subject: label(x), Issuer: issuerLabel(x),
		NotBefore: x.NotBefore.UTC(), NotAfter: x.NotAfter.UTC(), Key: keyString(x),
		Signature: x.SignatureAlgorithm.String(), SHA256: fingerprint(x), DNSNames: x.DNSNames,
		SelfSigned: selfSigned(x),
	}
	s.DaysLeft = int(x.NotAfter.Sub(opt.Now).Hours() / 24)
	if x.NotAfter.Before(opt.Now) {
		s.DaysLeft = -int(opt.Now.Sub(x.NotAfter).Hours() / 24)
	}
	return s
}

func checkCert(c *Cert, opt Options) []Finding {
	x := c.X
	var out []Finding
	add := func(id, sev, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Pos: c.Pos, Message: fmt.Sprintf(format, args...)})
	}
	self := selfSigned(x)
	ca := isCA(x)
	leaf := !ca && !(x.Version < 3 && self)

	switch {
	case opt.Now.After(x.NotAfter):
		add("CW001", Error, "expired on %s (%d days ago)", day(x.NotAfter), int(opt.Now.Sub(x.NotAfter).Hours()/24))
	case opt.Now.Before(x.NotBefore):
		add("CW003", Error, "not valid until %s", day(x.NotBefore))
	case x.NotAfter.Sub(opt.Now) < time.Duration(opt.WarnDays)*24*time.Hour:
		add("CW002", Warning, "expires on %s, in %d days (the warning threshold is %d)", day(x.NotAfter),
			int(x.NotAfter.Sub(opt.Now).Hours()/24), opt.WarnDays)
	}

	switch k := x.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < 2048 {
			add("CW010", Error, "RSA key is %d bits; 2048 is the minimum", bits)
		}
		if k.E < 65537 {
			add("CW013", Warning, "RSA public exponent is %d; the Baseline Requirements ask for at least 65537", k.E)
		}
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
		default:
			add("CW011", Error, "elliptic curve %s is not one of P-256, P-384, P-521", k.Curve.Params().Name)
		}
	}
	// Checked by algorithm rather than key type: crypto/dsa is deprecated, and this only reads.
	if x.PublicKeyAlgorithm == x509.DSA {
		add("CW012", Error, "DSA keys are not accepted by current TLS stacks")
	}

	switch x.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		// A root's own signature over itself is not what clients trust it for.
		if !(self && ca) {
			add("CW020", Error, "signed with %s, which can be forged or is broken", x.SignatureAlgorithm)
		}
	}

	// A trust anchor's serial number is never checked by a client, and real roots have serial 0, so
	// for a self-signed CA these are notes and not errors.
	serialSev := Error
	if self && ca {
		serialSev = Info
	}
	if sign := x.SerialNumber.Sign(); sign <= 0 {
		add("CW061", serialSev, "serial number is %s; RFC 5280 requires a positive integer", x.SerialNumber)
	} else if x.SerialNumber.BitLen() > 159 {
		add("CW061", serialSev, "serial number is longer than 20 octets, which RFC 5280 forbids")
	} else if x.SerialNumber.BitLen() < 64 && !(self && ca) {
		add("CW060", Warning, "serial number has only %d bits; the Baseline Requirements ask for 64 bits of randomness", x.SerialNumber.BitLen())
	}

	if !self && len(x.AuthorityKeyId) == 0 {
		add("CW062", Warning, "no Authority Key Identifier, so a client cannot tell which issuer key to use after a key rollover")
	}
	if ca && len(x.SubjectKeyId) == 0 {
		add("CW063", Info, "a CA certificate without a Subject Key Identifier")
	}

	if leaf {
		out = append(out, checkLeaf(c, opt, self)...)
	}
	if ca && !self && len(x.DNSNames) > 0 && hasServerAuth(x) {
		add("CW052", Warning, "a CA certificate that also names hosts and allows serverAuth: deployed as a server certificate, its key could issue certificates")
	}
	if ca && x.KeyUsage != 0 && x.KeyUsage&x509.KeyUsageCertSign == 0 {
		add("CW053", Error, "a CA certificate whose key usage does not include keyCertSign")
	}
	for _, u := range x.UnhandledCriticalExtensions {
		add("CW090", Info, "critical extension %s is not understood by this tool", u)
	}
	return out
}

func checkLeaf(c *Cert, opt Options, self bool) []Finding {
	x := c.X
	var out []Finding
	add := func(id, sev, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Pos: c.Pos, Message: fmt.Sprintf(format, args...)})
	}
	server := len(x.ExtKeyUsage) == 0 && len(x.UnknownExtKeyUsage) == 0
	for _, u := range x.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			server = true
		}
	}

	if self {
		add("CW088", Info, "self-signed and not a CA: clients accept it only if it is trusted or pinned explicitly")
	}
	if len(x.ExtKeyUsage) > 0 && !server {
		if len(x.DNSNames) > 0 {
			add("CW050", Error, "has DNS names but its extended key usage does not include serverAuth")
		}
	} else if len(x.ExtKeyUsage) == 0 && len(x.UnknownExtKeyUsage) == 0 {
		add("CW051", Info, "no extended key usage, so the certificate is valid for any purpose")
	}
	if x.KeyUsage != 0 {
		need := x509.KeyUsageDigitalSignature
		if _, isRSA := x.PublicKey.(*rsa.PublicKey); isRSA {
			need |= x509.KeyUsageKeyEncipherment
		}
		if x.KeyUsage&need == 0 {
			add("CW053", Warning, "key usage %s does not allow a TLS handshake", usageString(x.KeyUsage))
		}
	}

	if d := maxValidityDays(x.NotBefore); !self && d > 0 && x.NotAfter.Sub(x.NotBefore) > time.Duration(d)*24*time.Hour {
		add("CW030", Warning, "valid for %d days; publicly trusted TLS certificates issued on %s are limited to %d (not binding on a private CA)",
			int(x.NotAfter.Sub(x.NotBefore).Hours()/24), day(x.NotBefore), d)
	}

	if !server {
		return out
	}
	if len(x.DNSNames) == 0 && len(x.IPAddresses) == 0 {
		add("CW040", Error, "no subject alternative name; browsers and Go ignore the common name")
	} else if cn := x.Subject.CommonName; cn != "" && strings.Contains(cn, ".") && !strings.ContainsAny(cn, " ") && !covered(cn, x) {
		add("CW041", Warning, "common name %q is not among the subject alternative names", cn)
	}
	wild := false
	for _, n := range x.DNSNames {
		if strings.Contains(n, "*") {
			wild = true
			if !strings.HasPrefix(n, "*.") || strings.Count(n, "*") != 1 || strings.Count(n, ".") < 2 {
				add("CW042", Error, "wildcard name %q is not of the form *.example.com", n)
			}
		}
		if internalName(n) {
			add("CW044", Warning, "name %q is not a public DNS name; public CAs may not issue it", n)
		}
	}
	for _, ip := range x.IPAddresses {
		if isPrivateIP(ip) {
			add("CW044", Warning, "address %s is a private or loopback address; public CAs may not issue it", ip)
		}
	}
	if wild {
		add("CW043", Info, "wildcard certificate: one key compromise exposes every name under it")
	}
	if !self && len(x.OCSPServer) == 0 && len(x.CRLDistributionPoints) == 0 {
		add("CW064", Info, "no OCSP responder or CRL distribution point, so revocation cannot be checked")
	}
	return out
}

func hasServerAuth(x *x509.Certificate) bool {
	for _, u := range x.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// maxValidityDays is the longest validity the CA/Browser Forum Baseline Requirements allowed for a
// publicly trusted TLS certificate issued on notBefore. Later scheduled reductions are not applied.
func maxValidityDays(notBefore time.Time) int {
	switch {
	case notBefore.Before(time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)):
		return 0 // the older 39-month rule is not enforced
	case notBefore.Before(time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC)):
		return 825
	case notBefore.Before(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)):
		return 398
	default:
		return 200
	}
}

func covered(cn string, x *x509.Certificate) bool {
	for _, n := range x.DNSNames {
		if strings.EqualFold(n, cn) {
			return true
		}
		if strings.HasPrefix(n, "*.") && strings.Count(strings.ToLower(cn), ".") == strings.Count(n, ".") &&
			strings.HasSuffix(strings.ToLower(cn), strings.ToLower(n[1:])) {
			return true
		}
	}
	for _, ip := range x.IPAddresses {
		if ip.String() == cn {
			return true
		}
	}
	return false
}

func internalName(n string) bool {
	n = strings.ToLower(strings.TrimSuffix(n, "."))
	if n == "" || strings.HasPrefix(n, "*") && !strings.Contains(n[1:], ".") {
		return false
	}
	if !strings.Contains(n, ".") {
		return true
	}
	for _, s := range []string{".local", ".internal", ".lan", ".corp", ".home", ".intranet", ".localdomain", ".test", ".example", ".invalid", ".localhost"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func usageString(u x509.KeyUsage) string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"},
	}
	var parts []string
	for _, n := range names {
		if u&n.bit != 0 {
			parts = append(parts, n.name)
		}
	}
	return strings.Join(parts, "+")
}
