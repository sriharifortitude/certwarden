# 2. What counts as a chain

Status: accepted

## Context

The same file extension holds very different things: `fullchain.pem` (a leaf, then its
issuers), `chain.pem` (only intermediates), `ca-bundle.crt` (150 unrelated roots), or a
directory dump of several servers' certificates. Order and gap checks are right for the
first two and pure noise for the others.

## Decision

A file is analysed as a chain when its end can be found without guessing.

- A certificate is an *end* if it issues no other certificate in the file. Issuing is
  decided by names (and key identifiers), not by a verified signature, so that a broken
  link (wrong key, an issuer that is not a CA) still has an end and can be reported.
- If exactly one end is an end-entity certificate, it is the leaf. A CA beside it that
  connects to nothing is then a stray (CW082), and the leaf's missing issuer is a gap
  (CW081).
- Otherwise, if there is exactly one end, the file is a CA chain, and it is checked the
  same way.
- Otherwise it is a bundle: only duplicates are reported.

From the leaf, issuers are followed by name and verified signature. A SHA-1 or MD5 link is
treated as verified for this purpose, because the weak-algorithm rule reports it and the
chain should not also fall apart.

## What changed it

The first version took "exactly one non-CA certificate" as the leaf. Two tests showed that
was wrong. A certificate issued by another non-CA certificate (the issuer-is-not-a-CA case
this tool exists to catch) had two non-CA certificates, so it was skipped as a bundle. And
the "wrong intermediate deployed" case (a leaf next to a sibling CA) was missed when the
rule was tightened to "exactly one end". The two-step rule above handles both, and each
has a test. A third test caught a repeated certificate being reported both as a duplicate
and as a stray. Now it is only a duplicate.

## Consequences

- A trust store is never reported as out of order.
- A file holding two separate chains is treated as a bundle, so its gaps go unreported.
  That costs less than guessing which chain was meant.
