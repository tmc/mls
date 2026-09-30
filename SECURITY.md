# Security Policy

Package `github.com/tmc/mls` has not received an independent security
audit. The Security section of the package documentation says what it
claims and what it does not, including the side channels it does not
close.

## Supported Versions

The module is at v0, so its API may still change between minor
versions. Security fixes land on `main` and are released as a patch
to the latest minor version, currently v0.1.x; earlier minor versions
do not receive fixes.

## Reporting a Vulnerability

Report suspected vulnerabilities privately to Travis Cline at
<travis.cline@gmail.com>, or through GitHub's private vulnerability
reporting on the
[Security tab](https://github.com/tmc/mls/security/advisories/new).

Please do not open a public issue for a suspected vulnerability.
Expect an acknowledgement within a week. Once a fix is available, the
issue is published as a GitHub security advisory and reported to
the Go vulnerability database.
