# Snippet Window Limitations — Examples for Dev (Codex)
Date: 2026-10-20
Purpose: Demonstrate cases where the first 300 characters of a document are insufficient to answer the question.

## Category 1: Deep Fact (Fact is located after 300 chars)

### Example 1: PortSwigger Web Cache Poisoning
- URL: https://portswigger.net/web-security/web-cache-poisoning
- Question: "What is the role of 'unkeyed inputs' in cache poisoning?"
- Document recovered: The full HTML/Markdown of the page.
- Fact present in snippet (first 300 chars): General definition of web cache poisoning and its general impact.
- Fact needed for answer: The specific definition and behavior of "unkeyed inputs" (found in the "Unkeyed inputs" section, approx. 2000 characters in).

### Example 2: OWASP ASVS v5.0
- URL: https://owasp.org/www-project-application-security-verification-standard/
- Question: "What are the specific requirements for Level 3 (L3) authentication?"
- Document recovered: The ASVS standard documentation.
- Fact present in snippet (first 300 chars): Introduction to the ASVS and the purpose of the verification standard.
- Fact needed for answer: Detailed authentication requirements for L3 (found in the "Authentication" section, thousands of characters in).

### Example 3: HackerOne Report (Generic Example)
- URL: https://hackerone.com/reports/123456 (Representative)
- Question: "What was the exact bypass payload used to evade the WAF?"
- Document recovered: Full report text.
- Fact present in snippet (first 300 chars): Report title, bounty status, and a brief summary of the bug.
- Fact needed for answer: The specific HTTP request payload located in the "Reproduction Steps" section.

### Example 4: Complex CTF Write-up
- URL: https://github.com/ctf-writeups/example/blob/main/re/binary.md
- Question: "Which specific XOR key was used to decrypt the second stage payload?"
- Document recovered: The write-up markdown.
- Fact present in snippet (first 300 chars): Challenge name, category, and initial static analysis.
- Fact needed for answer: The key found in the "Decryption Logic" section near the end of the document.

## Category 2: Cross-Document Fact (Requires crossing two docs)

### Example 5: CVE to CWE Mapping
- URL 1: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- URL 2: https://cwe.mitre.org/data/definitions/502.html
- Question: "How does the JNDI lookup in Log4j specifically embody the 'untrusted data' principle of CWE-502?"
- Document recovered: The CVE details and the CWE definition.
- Fact present in snippet (first 300 chars):
    - Doc 1: Log4j vulnerability summary.
    - Doc 2: CWE-502 (Deserialization of Untrusted Data) general definition.
- Fact needed for answer: The logical connection between the JNDI lookup (Doc 1) and the "untrusted data" mechanism (Doc 2).

### Example 6: CISA KEV & NVD Correlation
- URL 1: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- URL 2: https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX
- Question: "On what date was CVE-2023-XXXX added to the CISA KEV, and what is its current NVD Base Score?"
- Document recovered: The KEV catalog and the NVD entry.
- Fact present in snippet (first 300 chars):
    - Doc 1: Catalog header/intro.
    - Doc 2: CVE summary.
- Fact needed for answer: The specific entry date in the KEV table and the numerical score in the NVD "CVSS" section.
