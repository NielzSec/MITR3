# Security Policy

## Intended use

MITR3 supports authorized security engineering, testing, research, reverse engineering, and defensive validation. Use it only on systems for which you have explicit authorization.

## Reporting a vulnerability

Do not publish exploitable details, credentials, customer data, or private evidence in public issues. Contact the repository owner privately through the GitHub profile to coordinate disclosure.

## Sensitive data policy

Never commit:
- API keys, access tokens, passwords, private keys, certificates, or connection strings.
- Cookies, session identifiers, authorization headers, browser profiles, or raw HTTP captures.
- Customer or third-party personal data, private engagement reports, or non-public vulnerability evidence.
- Local databases, indexes, caches, logs, screenshots, and generated execution artifacts.
- Machine-specific configuration containing usernames, hostnames, private IPs, or secret paths.

If a secret is committed, removing it from the latest commit is insufficient. Revoke or rotate it first, then coordinate history cleanup.
