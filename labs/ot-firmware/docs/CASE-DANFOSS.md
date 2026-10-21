# CASE-DANFOSS — Team82's AK-SM 800A research and the three 2025 CVEs

**Status:** public-source research note, 2026-10-21. Web and documents only — no
device, no scan, no exploit code. **Inferences are marked** as such.

## 1. What the record establishes

The Danfoss AK-SM 800A aggregates supermarket refrigeration controllers and
exposes a browser interface for temperatures, alarms, schedules, users and e-mail
notification. Team82 counted ~2,765 internet-exposed interfaces on Shodan/Censys
and chose that web surface as the entry point
([Team82](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)).

Three CVEs came out of that work (advisories 2025; architecture write-up 9 Aug
2026, Team82 above;
[Danfoss DSA-2025-03-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/);
[DSA-2025-08-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/)).

**Fix version — confirmed.** Danfoss states R4.2 remediates CVE-2025-41450 and
R4.3.1 remediates CVE-2025-41451/41452; CISA repeats the split
([ICSA-25-140-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03)).
PATCHED = R4.3.1 and newer per vendor; availability on the download page is **not
verified here.**



## 2. The documented component chain

Team82 reconstructed four hops between client and privileged operation:

1. **External nginx** — reverse proxy on the management ports; routes `.cgi`
   suffixes to a CGI instance (`nginx.conf`).
2. **`sm_fcgi_app`** — initial handling (`sm_fcgi_app.conf`), then forwards via
   `forward_xml_request`.
3. **Internal nginx** — local listener; forwards `.cgi` URLs to a CGI service in
   `Task_Web`, a task created by `sm_app`.
4. **`sm_app`** — parses and dispatches to handlers (`xml_get_data` for actions
   such as `getauth`; separate handler for `load_nginx_headers`).

The internet-facing nginx includes `headers.conf`, which the application can
rewrite at runtime (Team82). **Inference (mine):** the design assumes anything on
the internal listener was already authenticated at hop 2 — Team82 does not state
this; it is the contract worth testing, because that is where hop-to-hop trust
usually breaks.

## 3. The three CVEs

| CVE | Class (CWE) | CVSS v3.1 / v4.0 | Precondition | Documented mechanism | Fixed in |
|---|---|---|---|---|---|
| CVE-2025-41450 | Improper authentication — CWE-287 (CISA); CWE-305 (Danfoss/NVD) | 8.2 / 7.3 | Web reach; no credentials | `xml.cgi?action=getauth` has a second path, gated by two redacted attributes, that checks `check_code_of_day` — a password derived from device date/time — instead of the configured credential; success yields an admin session | R4.2 |
| CVE-2025-41451 | OS command injection — CWE-77 | 7.6 / 8.7 | Authenticated session | The alarm-to-mail ("SMTP") password, config item `0x1be1`, is formatted into an OS shell command without neutralisation | 4.3.1 |
| CVE-2025-41452 | External control of configuration setting — CWE-15 | 5.4 / 6.8 | Authenticated session | `action=load_nginx_headers` uploads a `headers.conf`, replaces the file included by the external nginx and reloads it; an implanted route raises an unhandled exception that kills `sm_app` (repeatable DoS) | 4.3.1 |

Sources: CISA for scores, vectors and ranges; Team82 for mechanisms; Danfoss for
the affected ranges.

Two discrepancies are worth recording. First, Danfoss describes 41450's impact
narrowly (a report leaking IPs, usernames, store names) while Team82 describes a
full admin session; **inference** — the advisory states one demonstrated
consequence, not the ceiling. Second, Team82 says R4.3.1 addresses "the
vulnerabilities described in this research" (all three), while vendor and CISA
split 41450 to R4.2 — a fleet on R4.2 is patched for the bypass only.

## 4. Static review of an extracted tree, per class

Read configuration before binaries: which process listens where, which runs as root
from init, which file includes which.

**Auth bypass (41450 shape).** In `sm_fcgi_app`, look for session state set before
`forward_xml_request` with no credential read on that path. In `sm_app`, start at
the `getauth` dispatch and ask whether any branch mints a session before touching
the credential store. Look for date/time calls (`time`, `localtime`, `strftime`)
near a password comparison, and for a comparison whose right side is computed
rather than loaded. Team82 redacted the attribute names and algorithm; any public
"reproduction" is a stand-in, including the PoC NVD lists.

**Command injection (41451 shape).** Follow the value, not the string table:
alarm/mail setter → stored field → command construction → `system`/`popen`.
Indicators: a format string placing a config value into `%s` inside a shell
command, `sendmail`/`msmtp` strings, and single-quote wrapping that does not reject
quotes in input. Check the builder's effective UID — a root `sm_app` turns a config
field into root code execution.

**Config write / DoS (41452 shape).** Locate the `fopen(..., "w")` behind
`xml_load_nginx_headers`: is the destination the file the external nginx includes,
is there a directive allowlist or only a length check, is reload a signal or
`system()`? Then read the error path — a dispatch function with no fallback for
unknown actions is the static shadow of the crash Team82 observed.

## 5. The French supermarket incidents (October 2026)

On 11–12 October 2026, hundreds of French supermarkets were forced into
sustained defrost, spoiling food and causing small fires
([BBC](https://www.bbc.com/news/articles/crq5nzxv9q4yo);
[Reuters](https://www.reuters.com/legal/litigation/investigators-hunt-french-supermarket-fridge-hackers-no-claim-responsibility-2026-10-13/)).
ANSSI's alert covers Danfoss AK-SC/AK-SM, Copeland xweb and Dixell xweb; it
recommends removing internet exposure, updating firmware
([CERTFR-2026-ALE-012](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-012/)).
Danfoss said units ran outdated firmware on older models (BBC); the mechanism is
not publicly known (Reuters). **No source reviewed here — Claroty, Danfoss, CISA,
ANSSI, Reuters, BBC — claims these CVEs were the vector used in France.** CISA's
"no known public exploitation" line dates to the advisory's last revision (26 Aug
2025), predates the incident, and says nothing about Oct 2026. Absence of
attribution is not evidence of non-use (**inference**); the link is unproven and
must not be upgraded to fact.

## 6. What transfers to our lab

| CVE class | Concrete fwlab / Ghidra indicator | In our fixture? |
|---|---|---|
| Header trust (41450 shape) | `auth_strings` queue reason (`X-`, `session`, `strcmp`); decompiled `*.interesting.c` showing `strstr` on the raw request buffer evaluated before the session check, plus a second build lacking the branch | Yes, synthetic: `X-Lab-Admin: 1` skips the `/admin` check; v2 removes it |
| Shell sink (41451) | `spawn_strings` reason (`system`, `popen`, `execve`, `/bin/sh`); xref from a config-set handler to the sink; setuid bit on the caller | No — no config-to-shell path |
| Config write (41452) | No dedicated rule. Manual: `in_web_root` binaries plus write-mode `fopen`, `nginx`, `reload`/`HUP` strings, then the same delta check | No |
| Version delta | `fwlab diff v1.inv.json v2.inv.json` → one modified ELF at the boundary | Yes, synthetic v1↔v2 |

The transferable asset is the *order of checks*, not the topology: our fixture is
one CGI; Danfoss had four components. `fwlab` explains *why* a binary was queued
(`in_web_root` 30, `auth_strings` 25, `setuid` 20, `spawn_strings` 15); it never
says the check is wrong — that still needs the two-address sentence in METHOD.md.
**No fixture evidence reproduces a Danfoss bug**; `X-Lab-Admin` is a teaching
label, not a claim about real header names.

## 7. Open questions

- Which component owns the credential store, and is the daily code compared before
  or after that read?
- Does the internal nginx enforce anything, or is loopback the only control?
  (`forward_xml_request` is the first hop to look at.)

## References

1. Team82, "Freeze the Controller, Defrost the Food" — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
2. Danfoss DSA-2025-03-01 — https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-03-01/
3. Danfoss DSA-2025-08-01 — https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/
4. CISA ICSA-25-140-03 — https://www.cisa.gov/news-events/ics-advisories/icsa-25-140-03
5. NVD — CVE-2025-41450/41451/41452 detail pages — https://nvd.nist.gov/vuln/detail/CVE-2025-41450 etc.
6. CERT-FR CERTFR-2026-ALE-012 — https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-012/
7. BBC — https://www.bbc.com/news/articles/crq5nzxv9q4yo
8. Reuters — https://www.reuters.com/legal/litigation/investigators-hunt-french-supermarket-fridge-hackers-no-claim-responsibility-2026-10-13/
9. Team82 dashboard — CVE pages — https://claroty.com/team82/disclosure-dashboard/cve-2025-41450 etc.
