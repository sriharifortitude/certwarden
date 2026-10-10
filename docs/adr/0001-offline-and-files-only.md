# 1. Offline, and files only

Status: accepted

## Context

Tools that inspect certificates usually connect to a host (`openssl s_client`, testssl.sh,
SSL Labs) or query OCSP, CRLs and Certificate Transparency logs. That answers "what does
this server send right now". It does not answer the question asked before a deployment,
in CI, when the certificate is a file in a pull request and the server does not have it
yet. It also brings network access, timeouts and third-party services into a build step.

## Decision

certwarden reads files and nothing else. It never opens a socket, follows an AIA URL, or
asks a revocation service. Where the network would help, it says where to look: a gap in
a chain names the issuer's AIA address instead of fetching it.

## Consequences

- It runs in a locked-down CI job and gives the same answer every time for the same files
  and `--now`, which is what makes the README's example testable.
- A revoked certificate passes. The README says so first among the limits.
- To audit a live server, the user saves its chain first. That is one extra command, and
  it keeps the tool simple enough to trust.
