package certs

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// checkChain looks at how the certificates in one file relate to each other.
//
// A file is read as one chain (the shape of fullchain.pem) when exactly one certificate in it issues
// nothing else in it. A bundle of unrelated roots, or of several leaves, is not a chain, so it gets
// only the duplicate check.
func checkChain(f *File) []Finding {
	var out []Finding
	add := func(pos int, id, sev, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Pos: pos, Message: fmt.Sprintf(format, args...)})
	}

	seen := map[string]int{}
	for _, c := range f.Certs {
		fp := string(c.X.Raw)
		if first, dup := seen[fp]; dup {
			add(c.Pos, "CW084", Warning, "the same certificate appears again; it is already #%d", first)
		} else {
			seen[fp] = c.Pos
		}
	}
	if len(f.Certs) < 2 {
		return out
	}

	// The end of the chain is a certificate that issues nothing else in the file. Judging by names
	// alone finds it even when an issuer is wrong or not a CA. If one such end is an end-entity
	// certificate it is the leaf, and a CA beside it that connects to nothing is a stray; otherwise
	// there must be exactly one end, or the file is a bundle and not a chain.
	var ends, leaves []int
	for i, c := range f.Certs {
		issues := false
		for j, other := range f.Certs {
			if i == j || bytes.Equal(c.X.Raw, other.X.Raw) {
				continue
			}
			if linked, _ := signedBy(other.X, c.X); linked {
				issues = true
				break
			}
		}
		if issues {
			continue
		}
		ends = append(ends, i)
		if roleOf(c.X) == RoleLeaf {
			leaves = append(leaves, i)
		}
	}
	var leafIdx int
	switch {
	case len(leaves) == 1:
		leafIdx = leaves[0]
	case len(leaves) == 0 && len(ends) == 1:
		leafIdx = ends[0]
	default:
		return out
	}

	// Walk from the leaf through issuers.
	used := map[int]bool{leafIdx: true}
	chain := []int{leafIdx}
	for {
		cur := f.Certs[chain[len(chain)-1]].X
		next := -1
		for i, c := range f.Certs {
			if used[i] || bytes.Equal(c.X.Raw, cur.Raw) {
				continue
			}
			if linked, ok := signedBy(cur, c.X); linked && ok {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		used[next] = true
		chain = append(chain, next)
	}

	last := f.Certs[chain[len(chain)-1]]
	if m := firstMismatch(f, last); m != nil {
		add(m.child.Pos, "CW086", Error, "names #%d as its issuer, but the signature does not verify with that certificate's key", m.parent.Pos)
	}

	// Order: each issuer should be the next certificate in the file.
	for i := 0; i+1 < len(chain); i++ {
		a, b := f.Certs[chain[i]], f.Certs[chain[i+1]]
		if b.Pos != a.Pos+1 {
			add(a.Pos, "CW080", Warning, "its issuer (%s) is #%d, not the next certificate in the file; strict clients reject chains out of order",
				label(b.X), b.Pos)
			break
		}
	}

	// A repeated certificate is reported as a duplicate, not also as stray.
	usedRaw := map[string]bool{}
	for i := range used {
		usedRaw[string(f.Certs[i].X.Raw)] = true
	}
	var leftovers []*Cert
	for i, c := range f.Certs {
		if !used[i] && !usedRaw[string(c.X.Raw)] {
			leftovers = append(leftovers, c)
		}
	}
	lastSelf := selfSigned(last.X)
	if len(leftovers) > 0 {
		if !lastSelf {
			msg := fmt.Sprintf("the chain from the leaf stops here: its issuer %q is not in this file", issuerLabel(last.X))
			if len(last.X.IssuingCertificateURL) > 0 {
				msg += "; its AIA extension says the issuer is at " + last.X.IssuingCertificateURL[0]
			}
			add(last.Pos, "CW081", Error, "%s", msg)
		}
		for _, c := range leftovers {
			add(c.Pos, "CW082", Warning, "is not part of the chain that leads from the leaf")
		}
	}
	if len(chain) > 1 && lastSelf {
		add(last.Pos, "CW083", Info, "the chain includes its root; servers need not send it, because clients already hold it")
	}

	// Constraints along the chain.
	for i := 0; i+1 < len(chain); i++ {
		child, parent := f.Certs[chain[i]], f.Certs[chain[i+1]]
		p := parent.X
		if !p.BasicConstraintsValid || !p.IsCA {
			add(parent.Pos, "CW087", Error, "issued #%d but is not marked as a CA (basicConstraints CA:TRUE)", child.Pos)
		}
		if p.KeyUsage != 0 && p.KeyUsage&x509.KeyUsageCertSign == 0 {
			add(parent.Pos, "CW087", Error, "issued #%d but its key usage lacks keyCertSign", child.Pos)
		}
		if limit, set := pathLimit(p); set {
			below := i // CA certificates between the leaf and this parent
			if below > limit {
				add(parent.Pos, "CW087", Error, "path length constraint %d is exceeded: %d intermediate CA certificate(s) lie below this one",
					limit, below)
			}
		}
		if child.X.NotAfter.After(p.NotAfter) {
			add(child.Pos, "CW085", Warning, "is valid until %s, longer than its issuer #%d (until %s)", day(child.X.NotAfter),
				parent.Pos, day(p.NotAfter))
		}
	}
	return out
}

type pair struct{ child, parent *Cert }

// firstMismatch looks for a certificate in the file whose subject matches the issuer name of the
// chain's last certificate, yet whose key did not make its signature. The walk through issuers
// stops at such a link, so the end of the chain is where it shows.
func firstMismatch(f *File, end *Cert) *pair {
	for _, c := range f.Certs {
		if bytes.Equal(c.X.Raw, end.X.Raw) {
			continue
		}
		if linked, ok := signedBy(end.X, c.X); linked && !ok {
			return &pair{child: end, parent: c}
		}
	}
	return nil
}

// pathLimit returns the CA's pathLenConstraint and whether it has one.
func pathLimit(c *x509.Certificate) (int, bool) {
	if !c.BasicConstraintsValid || !c.IsCA {
		return 0, false
	}
	if c.MaxPathLen > 0 || (c.MaxPathLen == 0 && c.MaxPathLenZero) {
		return c.MaxPathLen, true
	}
	return 0, false
}
