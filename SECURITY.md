# Security policy

LogCarve is currently a **preview for local evaluation**. This document
describes how to report a suspected vulnerability. Engineering security
guidance for contributors and reviewers lives in
[docs/security.md](docs/security.md) and
[privacy and data egress](docs/privacy-and-security.md).

## Report a vulnerability privately

Please report suspected security vulnerabilities **privately** through
GitHub:

- [Report a vulnerability privately](https://github.com/abbottis/logcarve/security/advisories/new)

Do not open a public issue for a suspected vulnerability.

## Private reports versus public bugs

- **Private vulnerability report:** anything that could weaken
  authentication, authorization, session handling, token handling,
  input isolation, pseudonymization, the encrypted original-IP store,
  or the model data-egress boundary, or that could leak raw log lines,
  original client addresses, secrets, or credentials.
- **Public issue:** a reproducible functional bug with no security
  impact (for example wrong counts, broken sorting, unclear text).
  If you are unsure, report privately first.

## What to include

- The version you evaluated (commit hash and branch, for example the
  current preview branch) and the environment (Python version, Docker
  image, browser) where applicable.
- Steps to reproduce with **synthetic data only**, plus the expected
  and actual behavior.
- The impact you see, without exploiting it further than needed to
  demonstrate the issue.

## What not to send

- No real access logs, raw log lines, original client addresses, or
  production configuration.
- No passwords, tokens, session cookies, private keys, or provider
  credentials.
- No personal data. Keep user names, host names, and addresses
  synthetic or redacted.

## Scope notes

- The actively evaluated version is the current preview. This policy
  does not name supported releases.
- There is no promised response time (SLA), no bug-bounty program,
  and no production certification in this preview.
