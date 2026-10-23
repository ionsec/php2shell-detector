# Security policy

## Supported versions

Only the latest build on `main` is supported. Pin a tag for production use.

## Reporting a vulnerability

Report privately — do not open a public issue.

- Email: info@ionsec.io
- or https://github.com/ionsec/php2shell-detector/security/advisories/new

Include: affected check (posture / log scan / drift / rules), how to reproduce,
and where the fingerprint logic or threshold fails. Reports about the PHP
vulnerabilities themselves belong with the PHP project, not here.

## Scope notes

This package intentionally opens no sockets. Findings of the log scan are
attempt evidence, not proof of execution; the drift check reads local files
only. See "Honest limits" in the README before relying on a verdict.
