// Package certs reads certificate files and audits what is in them.
//
// Every input is treated as untrusted: files are size-capped, the number of
// certificates per file and files per run are capped, symbolic links met while
// walking a directory are not followed, and private keys found in a file are
// reported without being decoded.
package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxFileBytes is the largest file that will be read.
	MaxFileBytes = 4 << 20
	// MaxCertsPerFile bounds one bundle. The Mozilla root store is about 150.
	MaxCertsPerFile = 500
	// MaxFiles bounds a directory walk.
	MaxFiles = 20000
)

var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".der": true, ".cert": true, ".ca-bundle": true,
}

// Cert is one parsed certificate and where it came from.
type Cert struct {
	// Pos is the 1-based position in its file.
	Pos int
	X   *x509.Certificate
}

// File is everything found in one file.
type File struct {
	Path  string
	Certs []*Cert
	// Findings are file-level problems: an unreadable file, a private key, a bad block.
	Findings []Finding
}

// privateKeyBlock finds PEM private key headers in raw bytes, whether or not the block decodes.
var privateKeyBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

// Load reads each path: a file, or a directory searched recursively for certificate files.
func Load(paths []string) ([]*File, error) {
	var files []*File
	seen := map[string]bool{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, unwrapPathError(err))
		}
		if !info.IsDir() {
			if !seen[p] {
				seen[p] = true
				files = append(files, loadFile(p, info.Size()))
			}
			continue
		}
		var found []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subdirectory should not stop the run
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			if certExtensions[strings.ToLower(filepath.Ext(path))] {
				found = append(found, path)
			}
			if len(found) > MaxFiles {
				return fmt.Errorf("more than %d certificate files under %s", MaxFiles, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(found)
		for _, f := range found {
			if seen[f] {
				continue
			}
			seen[f] = true
			size := int64(0)
			if fi, err := os.Stat(f); err == nil {
				size = fi.Size()
			}
			files = append(files, loadFile(f, size))
		}
	}
	return files, nil
}

func unwrapPathError(err error) error {
	if pe, ok := err.(*fs.PathError); ok {
		return pe.Err
	}
	return err
}

func loadFile(path string, size int64) *File {
	f := &File{Path: filepath.ToSlash(path)}
	if size > MaxFileBytes {
		f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error,
			Message: fmt.Sprintf("the file is %d bytes; larger than %d MiB, so it was not read", size, MaxFileBytes>>20)})
		return f
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error, Message: "cannot be read: " + unwrapPathError(err).Error()})
		return f
	}
	parse(f, data)
	return f
}

// parse fills f from raw file contents. It is separate from loadFile so tests and the fuzzer can use it.
func parse(f *File, data []byte) {
	if n := len(privateKeyBlock.FindAll(data, 16)); n > 0 {
		f.Findings = append(f.Findings, Finding{ID: "CW070", Severity: Error,
			Message: fmt.Sprintf("the file contains %d private key block(s); keys do not belong in a certificate file, and this one was not decoded", n)})
	}
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		c, err := x509.ParseCertificate(data)
		if err != nil {
			f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error, Message: "not a certificate: " + firstLine(err)})
			return
		}
		f.Certs = append(f.Certs, &Cert{Pos: 1, X: c})
		return
	}
	rest := data
	blocks := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
		default:
			continue // CSRs, CRLs, keys (already reported) and so on
		}
		if len(f.Certs) >= MaxCertsPerFile {
			f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error,
				Message: fmt.Sprintf("more than %d certificates; the rest were not read", MaxCertsPerFile)})
			return
		}
		der := block.Bytes
		if block.Type == "TRUSTED CERTIFICATE" {
			// OpenSSL appends trust settings after the certificate; ParseCertificate rejects the tail.
			der = trimToCertificate(der)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error,
				Message: fmt.Sprintf("PEM block %d is not a usable certificate: %s", blocks, firstLine(err))})
			continue
		}
		f.Certs = append(f.Certs, &Cert{Pos: len(f.Certs) + 1, X: c})
	}
	if blocks == 0 && len(f.Findings) == 0 {
		f.Findings = append(f.Findings, Finding{ID: "CW071", Severity: Error, Message: "contains -----BEGIN but no valid PEM block"})
	}
}

// trimToCertificate cuts DER at the end of its first SEQUENCE.
func trimToCertificate(der []byte) []byte {
	if len(der) < 4 || der[0] != 0x30 {
		return der
	}
	l := int(der[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(der) < 2+n {
			return der
		}
		l = 0
		for _, b := range der[2 : 2+n] {
			l = l<<8 | int(b)
		}
		hdr = 2 + n
	}
	if hdr+l > len(der) {
		return der
	}
	return der[:hdr+l]
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
