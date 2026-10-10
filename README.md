# certwarden

[![CI](https://github.com/sriharifortitude/certwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/certwarden/actions/workflows/ci.yml)

Audits X.509 certificates and the chains in certificate files, offline: expiry, weak
keys and signature algorithms, names, key usage, and whether a `fullchain.pem` is
complete and in order. Go, standard library only, MIT.

## What it is for

Most certificate outages are not cryptography. They are a chain file deployed without
its intermediate, a chain in the wrong order that one strict client rejects, a
certificate that expired on a Sunday, or a private key pasted into the bundle that gets
copied to the web root. These are cheap to catch before deployment, in CI, from the
files alone:

<!-- demo:start -->
```
$ certwarden testdata/fullchain.pem --now 2026-10-10T00:00:00Z
testdata/fullchain.pem: 2 certificates, no findings
  #1 leaf www.example.org  [EC P-256, ECDSA-SHA256, 2026-09-10 to 2026-12-09, 60 days left]
  #2 CA   Example Trust Issuing CA  [EC P-256, ECDSA-SHA256, 2018-10-10 to 2034-10-10, 2922 days left]

$ certwarden testdata/expired.pem --now 2026-10-10T00:00:00Z
testdata/expired.pem: 2 certificates, 1 error, 0 warnings
  #1 leaf old.example.org  [EC P-256, ECDSA-SHA256, 2026-06-12 to 2026-09-19, expired 21 days ago]
  #2 CA   Example Trust Issuing CA  [EC P-256, ECDSA-SHA256, 2018-10-10 to 2034-10-10, 2922 days left]
  error   CW001 #1 expired on 2026-09-19 (21 days ago)

$ certwarden testdata/wrong-order.pem --now 2026-10-10T00:00:00Z
testdata/wrong-order.pem: 3 certificates, no errors, 1 warning
  #1 leaf www.example.org  [EC P-256, ECDSA-SHA256, 2026-09-10 to 2026-12-09, 60 days left]
  #2 root Example Trust Root  [EC P-256, ECDSA-SHA256, 2006-10-10 to 2046-10-10, 7305 days left]
  #3 CA   Example Trust Issuing CA  [EC P-256, ECDSA-SHA256, 2018-10-10 to 2034-10-10, 2922 days left]
  warning CW080 #1 its issuer (Example Trust Issuing CA) is #3, not the next certificate in the file; strict clients reject chains out of order
  info    CW083 #2 the chain includes its root; servers need not send it, because clients already hold it

$ certwarden testdata/missing-intermediate.pem --now 2026-10-10T00:00:00Z
testdata/missing-intermediate.pem: 2 certificates, 1 error, 1 warning
  #1 leaf api.example.org  [EC P-256, ECDSA-SHA256, 2026-09-10 to 2026-12-09, 60 days left]
  #2 CA   Example Trust Other CA  [EC P-256, ECDSA-SHA256, 2018-10-10 to 2034-10-10, 2922 days left]
  error   CW081 #1 the chain from the leaf stops here: its issuer "Example Trust Issuing CA" is not in this file; its AIA extension says the issuer is at http://ca.example.org/issuing.crt
  warning CW082 #2 is not part of the chain that leads from the leaf

$ certwarden testdata/weak.pem --now 2026-10-10T00:00:00Z
testdata/weak.pem: 1 certificate, 1 error, 0 warnings
  #1 leaf weak.example.org  [RSA 1024, ECDSA-SHA256, 2026-09-10 to 2026-12-09, 60 days left]
  error   CW010 #1 RSA key is 1024 bits; 2048 is the minimum
```
<!-- demo:end -->

The `--now` in the example pins the clock so the output stays the same; leave it out and
certificates are judged against the current time. Exit codes: 0 no errors, 1 at least one
error (or a warning, with `--strict`), 2 a usage error or a path that cannot be read.

## Usage

```bash
go install github.com/sriharifortitude/certwarden/cmd/certwarden@v0.1.0

certwarden /etc/nginx/certs/fullchain.pem
certwarden ./certs --warn-days 21 --strict      # a directory: .pem .crt .cer .der .cert .ca-bundle
certwarden fullchain.pem --json                 # findings plus each certificate's SHA-256 fingerprint
```

In CI, run it over the certificate files you are about to deploy and fail the job on
exit 1. It does not connect anywhere, so it needs no network and cannot be pointed at a
host; to audit what a server actually sends, save the chain first (for example with
`openssl s_client -showcerts`).

## Checks

| ID | Severity | What it finds |
|---|---|---|
| CW001 / CW003 | error | expired; not yet valid |
| CW002 | warning | expires within `--warn-days` (default 30) |
| CW010 | error | RSA key under 2048 bits |
| CW011 | error | an elliptic curve other than P-256, P-384, P-521 |
| CW012 | error | a DSA key |
| CW013 | warning | RSA public exponent below 65537 |
| CW020 | error | signed with MD2, MD5 or SHA-1 (not reported for a root's signature over itself, which no client relies on) |
| CW030 | warning | a leaf valid longer than the CA/Browser Forum allows for its issue date: 825 days from March 2018, 398 from September 2020, 200 from 15 March 2026. Binding only on publicly trusted certificates |
| CW040 | error | a server certificate with no subject alternative name |
| CW041 | warning | the common name is a host name that is not among the SANs |
| CW042 / CW043 | error / info | a wildcard that is not one leftmost label (`*.*.example.org`, `*.org`); any wildcard |
| CW044 | warning | an internal name (`.local`, `.internal`, a single label, …) or a private IP address in the SANs |
| CW050 / CW051 | error / info | DNS names but no serverAuth in the extended key usage; no extended key usage at all |
| CW052 | warning | a CA certificate that also names hosts and allows serverAuth |
| CW053 | error / warning | a CA without keyCertSign; a leaf whose key usage cannot do a TLS handshake |
| CW060 / CW061 | warning / error | a serial under 64 bits; a serial that is not positive or longer than 20 octets (only a note on a self-signed root, where real roots have serial 0) |
| CW062 / CW063 | warning / info | no Authority Key Identifier; a CA with no Subject Key Identifier |
| CW064 | info | a leaf with neither OCSP nor CRL information |
| CW070 | error | a private key in the file (detected by its header, never decoded or printed) |
| CW071 | error | a file or block that is not a readable certificate, with Go's reason |
| CW080 | warning | a chain out of order |
| CW081 | error | a gap: the leaf's chain stops at a certificate whose issuer is missing, while other certificates are present; names the AIA address when there is one |
| CW082 | warning | a certificate that is not part of the leaf's chain |
| CW083 | info | the chain includes its root |
| CW084 | warning | the same certificate twice |
| CW085 | warning | a certificate valid for longer than its issuer |
| CW086 | error | the issuer name matches a certificate in the file, but its key did not make the signature |
| CW087 | error | an issuer that is not a CA, lacks keyCertSign, or whose path length constraint is exceeded |
| CW088 | info | a self-signed certificate that is not a CA |
| CW090 | info | a critical extension Go does not understand |

A file is read as one chain when exactly one certificate in it issues nothing else in
it, or when exactly one leaf does. A bundle of roots (a trust store) is not a chain, so
it is not checked for order or gaps.
[ADR 2](docs/adr/0002-what-counts-as-a-chain.md) explains why the rule is phrased that
way and what changed it.

## Untrusted input

Certificate files come from vendors, tickets and other people's servers. A file over
4 MiB is not read; at most 500 certificates are read from one file and 20,000 files from
one directory; symbolic links met while walking a directory are not followed, and `.git`
directories are skipped. Private keys are found by their PEM header with a linear-time
regular expression and are never decoded, so a key in the wrong place is reported without
its contents being handled. Parsing is the standard library's `crypto/x509`.

## Tested

```bash
go test ./...                                                 # 71 tests and a fuzz target
go test -run x -fuzz FuzzParseAndAudit ./internal/certs       # the fuzz target on its own
```

The tests build their own CAs and certificates with `crypto/x509`, one defect at a time.
Certificates Go refuses to create are made in two other ways: a hand-built
`x509.Certificate` for a DSA key, exponent 3, serial 0 or a 21-octet serial; and, for an
MD5 signature, an RSA certificate whose algorithm identifier is swapped for another of
the same length. Go will still sign with SHA-1, so that test uses a real SHA-1
signature. Private keys used by tests are generated at test time, so no key-shaped text
is committed.

Fuzzing the parser and the audit together ran about a million inputs in 20 seconds
without a crash. A test also flips bytes throughout a three-certificate chain and cuts
it at many points.

I broke the code in 70 places on purpose and checked that a test fails each time. The
first run left 20 standing, which showed the tests were weaker than they looked. Eleven
had no test at all: DSA, exponent 3, P-521 accepted, a missing SKI, `ExtKeyUsageAny`, an
RSA leaf with only keyEncipherment, a short serial on a root, the wildcards `*.*.x.org`
and `*.org`, a common name that is not a host name, and a chain file with no leaf. Five
sat on a limit with no test near it: the 825-, 398- and 200-day validity limits, the 2020
start date, and the 20-octet serial. Two passed because a different rule raised the same
ID. One exposed dead code: a "server certificate that is also a CA" rule that could never
run, because such a certificate is classified as a CA first. It is now a rule about CA
certificates. Now 69 of 70 are caught. The remaining one is the symlink rule, whose test needs permission to create
symbolic links. That permission is missing on the Windows machine this was built on, so
the test skips there and runs on Linux CI.

**Against real certificates.**
- The Mozilla root bundle shipped with Git for Windows: 150 roots. It reports one
  expired root (Baltimore CyberTrust, which expired in May 2025 and is still in that
  bundle), three roots with public exponent 3, and eight with serial number 0. The
  last led to the change that makes a serial problem on a self-signed root a note, not
  an error: trust anchors are not checked for it, and an error on every trust store
  would be noise.
- The 438 certificate files in the Go source tree (424 parseable certificates, many of
  them deliberately broken test cases such as the NIST PKITS suite): no crash. Twelve
  are rejected by Go's parser and reported with its reason. Two private keys kept
  beside test certificates were found.

**Not tested:** certificates from a live public CA issued under the March 2026 200-day
rule (the fixtures are synthetic); RSA-PSS and Ed25519 certificates beyond parsing;
symbolic links on Windows; very large trust stores beyond the 150-root bundle.

## Limits

- **Offline, by design.** No OCSP, CRL or CT lookups, and no connection to a server. A
  revoked certificate looks fine here.
- **No trust decision.** It does not say whether a chain is trusted by any browser or
  operating system; it checks the files' internal consistency and the certificates'
  properties.
- **The Baseline Requirements move.** The validity limits are encoded as I read the
  CA/Browser Forum's schedule up to the 200-day stage; later stages are not applied, and
  a private CA is not bound by any of them.
- **Go's parser is strict.** A certificate that Go rejects (a negative serial, malformed
  policies) is reported as unreadable, with Go's reason, even if OpenSSL accepts it.

## Licence

MIT.
