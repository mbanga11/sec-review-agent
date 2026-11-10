# Phase 1 Notes: Scanners on NodeGoat

Target: OWASP NodeGoat (intentionally vulnerable Node.js/Express app)
Date: Nov 10, 2026

## Results summary

| Tool | Version | What it scans | Findings |
|---|---|---|---|
| Semgrep | 1.184.0 | Code patterns (SAST), `p/owasp-top-ten` | 21 |
| osv-scanner | 2.7.0 | Dependencies in package-lock.json (1,091 packages) | 201 vulns |
| gitleaks | 8.30.1 | Secrets across full git history (380 commits) | 5 |

## Fields to keep (for the Phase 3 wrappers)

**Semgrep** (`.results[]`)
- `check_id` (rule name, use the last part after the final `.`)
- `path`, `start.line`
- `extra.severity`, `extra.message`
- `extra.metadata.cwe`

**osv-scanner** (`.results[].packages[]`)
- `package.name`, `package.version`
- `vulnerabilities[].id` (GHSA / CVE)
- severity and fixed version
- Note: use `--output-file`, `--output` is deprecated

**gitleaks** (top-level array)
- `RuleID`, `File`, `StartLine`, `Commit`
- Always run with `--redact` so secret values never reach the LLM

## Semgrep vs. the agent

| Issue | Agent | Semgrep |
|---|---|---|
| Open redirect (index.js:72) | Yes | Yes (same line) |
| Insecure session cookies (server.js) | Yes | Yes |
| eval() code injection (contributions.js:32-34) | **Missed** | Yes |
| NoSQL injection via `$where` (allocations-dao.js:78) | Yes | Missed |
| SSRF (research.js) | Yes | Missed |
| Stored XSS (autoescape off) | Yes | Missed |
| IDOR (allocations.js) | Yes | Missed |
| Plaintext passwords (user-dao.js) | Yes | Missed |
| ReDoS (profile.js) | Yes | Missed |

Takeaway: scanners give exact lines and catch files the agent never opened.
The agent catches logic bugs that pattern matching can't (authorization, data flow).
Combine them: scanners find candidates, agent judges and fills gaps.

## Likely false positives / low value

- 5x `plaintext-http-link` in `app/views/tutorial/*.html`. Links in tutorial docs, not app risk.
- 6x `github-actions-mutable-action-tag`. Real supply-chain hygiene, but low severity.
- 6 cookie findings on server.js:78 are really 1 issue. Needs dedup.
- osv: many hits are dev/build tooling (`npm`, `brace-expansion`, `minimatch`), not runtime code.
- gitleaks: `generic-api-key` in test/dev config is likely demo secrets. Lower risk.
- gitleaks: `test.js` flagged twice in different commits. Same secret, needs dedup.

## Real findings worth highlighting

- `contributions.js` eval() injection (Semgrep only)
- `marked@0.3.5` (osv): planted vulnerable component, known XSS
- 2 private keys committed to git history (gitleaks): `artifacts/cert/server.key`, `app/cert/key.pem`

## Lessons for the wrappers (Phase 3)

- Raw output is too big for the LLM (201 osv vulns). Trim to top N, group by package, keep only high/critical.
- Deduplicate findings on the same file + line.
- osv exits with code 1 when it finds vulns. Treat that as success, not an error.
- gitleaks scans history, not just current files. A deleted secret still needs rotation.