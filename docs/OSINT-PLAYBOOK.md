# MITR3 OSINT Playbook

This playbook defines the standardized approach for Open Source Intelligence (OSINT) and Intelligence gathering for the MITR3 squad. All research must follow the evidence-first flow to ensure reproducibility and avoid cognitive bias.

## 1. Technical Resource Catalog

### Core Toolset (High Trust)
- **CyberChef**: Data transformation and decoding. [Link](https://gchq.github.io/CyberChef/)
- **Wayback Machine**: Historical web snapshots. [Link](https://web.archive.org/)
- **VirusTotal**: IOC reputation and static analysis. [Link](https://www.virustotal.com/gui/)
- **urlscan.io**: Web investigation and screenshotting. [Link](https://urlscan.io/)
- **Shodan**: Asset exposure and banner grabbing. [Link](https://shodan.io/)
- **Censys**: Asset enrichment and certificates. [Link](https://censys.io/domain)
- **GreyNoise**: Internet noise and scanner context. [Link](https://www.greynoise.io/viz/)
- **SecurityTrails**: Passive DNS and domain history. [Link](https://securitytrails.com/)
- **crt.sh**: Certificate Transparency logs. [Link](https://crt.sh/)
- **Wappalyzer**: Technology fingerprinting. [Link](https://www.wappalyzer.com/lookup/)

### Specialized Categories (Reference OSINT4ALL)
- **Infrastructure**: Domain / IP / DNS (51 sources), WHOIS (5 sources), Resolvers (6 sources).
- **Identity**: People (26 sources), Phone (27 sources), Email (26 sources), Username (19 sources).
- **Threat Intel**: Malware (14 sources), Threat Intel (17 sources), Darknet (15 sources), Data Dumps (16 sources).
- **Gov/LE**: Government (47 sources), Police / LE / Fed (43 sources), Public Records (45 sources).
- **Specialized**: Geo (18 sources), Maritime (18 sources), Flight Tracker (10 sources), Radio (18 sources).

## 2. MegaBrain Intelligence Queries

Use these patterns to extract actionable intel from the MegaBrain knowledge base:

- **Tool Discovery**: `mcp__megabrain__knowledge_search(query="best tool for [CATEGORY] OSINT")`
- **Entity Correlation**: `mcp__megabrain__knowledge_search(query="correlate [ENTITY_A] and [ENTITY_B] in OSINT sources")`
- **Infrastructure Mapping**: `mcp__megabrain__knowledge_search(query="find all known infrastructure associated with [TARGET]")`
- **TTP Identification**: `mcp__megabrain__knowledge_search(query="TTPs associated with [THREAT_ACTOR] in public reports")`
- **Evidence Verification**: `mcp__megabrain__knowledge_search(query="verify [INDICATOR] against known threat feeds")`

## 3. Evidence-First Research Flow

All OSINT tasks must follow this linear progression. Do not jump to conclusions without a recorded evidence chain.

### Phase 1: Hypothesis & Scope
1. **Define Objective**: What specifically are we looking for? (e.g., "Find the owner of domain X").
2. **Define Scope**: Which identifiers do we have? (IPs, emails, aliases).
3. **Hypothesize**: "If the target is [X], I expect to find [Y] in [SOURCE Z]".

### Phase 2: Tooling & Collection
1. **Passive First**: Use non-intrusive tools (crt.sh, SecurityTrails, Wayback Machine).
2. **Cross-Reference**: Validate a finding in one source with at least one other independent source.
3. **Record Raw Evidence**: Save raw output, screenshots, and URLs. Use absolute paths in the field journal.

### Phase 3: Analysis & Correlation
1. **Pivot**: Use discovered data (e.g., a unique email) to search for new identifiers.
2. **Filter Noise**: Use GreyNoise or internal baselines to discard common internet noise.
3. **Map Relationships**: Build a link graph between entities.

### Phase 4: Validation & Conclusion
1. **Confidence Rating**:
   - **High**: Multiple independent, high-trust sources.
   - **Medium**: Single reliable source or multiple low-trust sources.
   - **Low**: Unverified or single low-trust source.
2. **Final Report**: Present the findings as a chain of evidence leading to the conclusion.

---
**Owner**: Hermes (Intelligence & Coordination)
**Last Updated**: 2026-10-19
