# Security Review: NodeGoat

| | |
|---|---|
| Target | `NodeGoat` |
| Scanned | 2026-11-24T00:37:13+00:00 |
| Model | gemini-3.5-flash-lite (24 agent steps) |
| Scanners | Semgrep (SAST), osv-scanner (dependencies), gitleaks (secrets), plus LLM manual review |
| Run status | complete |

## Executive summary

**14 confirmed issues**, 0 needing review, 2 dismissed as false positives or duplicates.

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 8 | 3 | 3 | 0 | 0 |

**Fix first:**

1. **Eval Injection in contributions update** (critical) in `app/routes/contributions.js:32`
2. **Committed private SSL key (artifacts/cert/server.key)** (critical) in `artifacts/cert/server.key:1`
3. **Committed private SSL key (app/cert/key.pem)** (critical) in `app/cert/key.pem:1`
4. **Vulnerable Dependency: bson** (critical) in `package-lock.json`
5. **Vulnerable Dependency: fsevents** (critical) in `package-lock.json`
6. **Vulnerable Dependency: minimist** (critical) in `package-lock.json`

## Confirmed findings

### Critical (8)

#### #1 Eval Injection in contributions update

- **Severity:** Critical
- **Location:** `app/routes/contributions.js:32`
- **Found by:** semgrep
- **CWE:** CWE-95
- **Controls:** OWASP A05:2025 Injection; NIST SI-10; SOC 2 CC7.1, CC8.1

**Why it matters:** eval() is used directly on request body parameters preTax, afterTax, and roth, leading to arbitrary code execution (Eval Injection / SSJS Injection).

**Fix:** Use parseInt() or parseFloat() instead of eval() to parse numerical inputs.

```javascript
    30 |         /*jslint evil: true */
    31 |         // Insecure use of eval() to parse inputs
>   32 |         const preTax = eval(req.body.preTax);
    33 |         const afterTax = eval(req.body.afterTax);
    34 |         const roth = eval(req.body.roth);
```

#### #8 Committed private SSL key (artifacts/cert/server.key)

- **Severity:** Critical
- **Location:** `artifacts/cert/server.key:1`
- **Found by:** gitleaks
- **CWE:** CWE-321
- **Controls:** OWASP A04:2025 Cryptographic Failures; NIST SC-12; SOC 2 CC6.1

**Why it matters:** Private SSL/TLS key committed to repository under artifacts/cert/server.key.

**Fix:** Remove committed private keys from repository history and use generated keys locally/ephemerally.

#### #9 Committed private SSL key (app/cert/key.pem)

- **Severity:** Critical
- **Location:** `app/cert/key.pem:1`
- **Found by:** gitleaks
- **CWE:** CWE-321
- **Controls:** OWASP A04:2025 Cryptographic Failures; NIST SC-12; SOC 2 CC6.1

**Why it matters:** Private SSL/TLS key committed to repository under app/cert/key.pem.

**Fix:** Remove committed private keys from repository history.

#### #10 Vulnerable Dependency: bson

- **Severity:** Critical
- **Location:** `package-lock.json`
- **Found by:** osv-scanner
- **CWE:** CWE-1035
- **Controls:** OWASP A03:2025 Software Supply Chain Failures; NIST SI-2, RA-5; SOC 2 CC7.1, CC8.1

**Why it matters:** Vulnerable dependency bson (v1.0.9) with high/critical CVEs (CVSS 9.8).

**Fix:** Update bson package to a patched secure version.

#### #11 Vulnerable Dependency: fsevents

- **Severity:** Critical
- **Location:** `package-lock.json`
- **Found by:** osv-scanner
- **CWE:** CWE-1035
- **Controls:** OWASP A03:2025 Software Supply Chain Failures; NIST SI-2, RA-5; SOC 2 CC7.1, CC8.1

**Why it matters:** Vulnerable/malicious dependency fsevents (v1.2.9) with high/critical CVEs (CVSS 9.8).

**Fix:** Update fsevents package or remove if unused in target environment.

#### #12 Vulnerable Dependency: minimist

- **Severity:** Critical
- **Location:** `package-lock.json`
- **Found by:** osv-scanner
- **CWE:** CWE-1035
- **Controls:** OWASP A03:2025 Software Supply Chain Failures; NIST SI-2, RA-5; SOC 2 CC7.1, CC8.1

**Why it matters:** Vulnerable dependency minimist with high/critical CVEs (CVSS 9.8).

**Fix:** Update minimist package to a patched secure version.

#### #13 Vulnerable Dependency: set-value

- **Severity:** Critical
- **Location:** `package-lock.json`
- **Found by:** osv-scanner
- **CWE:** CWE-1035
- **Controls:** OWASP A03:2025 Software Supply Chain Failures; NIST SI-2, RA-5; SOC 2 CC7.1, CC8.1

**Why it matters:** Vulnerable dependency set-value with high/critical CVEs (CVSS 9.8).

**Fix:** Update set-value package to a patched secure version.

#### #14 Vulnerable Dependency: underscore

- **Severity:** Critical
- **Location:** `package-lock.json`
- **Found by:** osv-scanner
- **CWE:** CWE-1035
- **Controls:** OWASP A03:2025 Software Supply Chain Failures; NIST SI-2, RA-5; SOC 2 CC7.1, CC8.1

**Why it matters:** Vulnerable dependency underscore with high/critical CVEs (CVSS 9.8).

**Fix:** Update underscore package to a patched secure version.

### High (3)

#### #6 Hardcoded API Key / Secret in development config

- **Severity:** High
- **Location:** `config/env/development.js:18`
- **Found by:** gitleaks
- **CWE:** CWE-798
- **Controls:** OWASP A07:2025 Authentication Failures; NIST IA-5; SOC 2 CC6.1

**Why it matters:** Hardcoded generic API key / secret in development config file.

**Fix:** Remove hardcoded API keys/secrets and load them via environment variables.

#### #7 Hardcoded API Key / Secret in test config

- **Severity:** High
- **Location:** `config/env/test.js:6`
- **Found by:** gitleaks
- **CWE:** CWE-798
- **Controls:** OWASP A07:2025 Authentication Failures; NIST IA-5; SOC 2 CC6.1

**Why it matters:** Hardcoded secret/API key in test config file.

**Fix:** Remove hardcoded secrets and load them via environment variables.

#### #15 IDOR in allocations display via userId parameter

- **Severity:** High
- **Location:** `app/routes/allocations.js:18`
- **Found by:** manual
- **CWE:** CWE-639
- **Controls:** OWASP A01:2025 Broken Access Control; NIST AC-3, AC-6; SOC 2 CC6.1, CC6.3

**Why it matters:** Insecure Direct Object Reference (IDOR): userId is taken from req.params instead of the session, allowing any logged-in user to view arbitrary user allocation records by changing the parameter in the URL.

**Fix:** Take userId from the authenticated session instead of req.params.userId to prevent IDOR.

```javascript
    16 |         const {
    17 |             userId
>   18 |         } = req.params;
    19 |         const {
    20 |             threshold
```

### Medium (3)

#### #2 Open Redirect in /learn route

- **Severity:** Medium
- **Location:** `app/routes/index.js:72`
- **Found by:** semgrep
- **CWE:** CWE-601
- **Controls:** OWASP A01:2025 Broken Access Control; NIST SI-10; SOC 2 CC6.6, CC8.1

**Why it matters:** User-controlled query parameter req.query.url is passed directly to res.redirect() without validation, leading to open redirect vulnerability.

**Fix:** Validate the redirect URL against an allow-list or ensure it's a relative path before redirecting.

```javascript
    70 |     app.get("/learn", isLoggedIn, (req, res) => {
    71 |         // Insecure way to handle redirects by taking redirect url from query string
>   72 |         return res.redirect(req.query.url);
    73 |     });
    74 | 
```

#### #3 Insecure session cookie configuration

- **Severity:** Medium
- **Location:** `server.js:78`
- **Found by:** semgrep
- **CWE:** CWE-522
- **Controls:** OWASP A07:2025 Authentication Failures; NIST IA-5, SC-23; SOC 2 CC6.1

**Why it matters:** express-session is configured without explicit secure, httpOnly, custom cookie name, or domain/path attributes, exposing session cookies to potential theft via XSS or network sniffing.

**Fix:** Configure cookie options including httpOnly: true, secure: true (in production), custom cookie name, and domain/path settings.

```javascript
    76 | 
    77 |     // Enable session management using express middleware
>   78 |     app.use(session({
    79 |         // genid: (req) => {
    80 |         //    return genuuid() // use UUIDs for session IDs
```

#### #16 ReDoS vulnerability in bankRouting validation regex

- **Severity:** Medium
- **Location:** `app/routes/profile.js:59`
- **Found by:** manual
- **CWE:** CWE-1333
- **Controls:** OWASP A06:2025 Insecure Design; NIST SC-5, SI-10; SOC 2 CC7.1

**Why it matters:** Regular Expression Denial of Service (ReDoS) vulnerability due to catastrophic backtracking in regex /([0-9]+)+\#/.

**Fix:** Fix the regular expression to avoid catastrophic backtracking (e.g. remove the nested quantifier '+' inside the group).

```javascript
    57 |         // The Fix: Instead of using greedy quantifiers the same regex will work if we omit the second quantifier +
    58 |         // const regexPattern = /([0-9]+)\#/;
>   59 |         const regexPattern = /([0-9]+)+\#/;
    60 |         // Allow only numbers with a suffix of the letter #, for example: 'XXXXXX#'
    61 |         const testComplyWithRequirements = regexPattern.test(bankRouting);
```

## Dismissed

Flagged by a scanner but judged not to be a real risk, or a repeat of another finding.

| # | Location | Verdict | Reason |
|---|---|---|---|
| 4 | `app/views/tutorial/a2.html:207` | false positive | Tutorial documentation page link, not reachable by users as an exploit vector. |
| 5 | `.github/workflows/e2e-test.yml:16` | false positive | CI/CD workflow configuration file, not an application code vulnerability reachable by end users. |

## Compliance impact

Each confirmed finding is mapped from its CWE to the controls below (see `data/cwe_controls.json`).

### OWASP Top 10:2025

| Control | Findings |
|---|---|
| A03:2025 Software Supply Chain Failures | #10, #11, #12, #13, #14 |
| A07:2025 Authentication Failures | #3, #6, #7 |
| A01:2025 Broken Access Control | #2, #15 |
| A04:2025 Cryptographic Failures | #8, #9 |
| A05:2025 Injection | #1 |
| A06:2025 Insecure Design | #16 |

### NIST SP 800-53 Rev. 5

| Control | Findings |
|---|---|
| RA-5 | #10, #11, #12, #13, #14 |
| SI-2 | #10, #11, #12, #13, #14 |
| IA-5 | #3, #6, #7 |
| SI-10 | #1, #2, #16 |
| SC-12 | #8, #9 |
| AC-3 | #15 |
| AC-6 | #15 |
| SC-23 | #3 |
| SC-5 | #16 |

### SOC 2 Trust Services Criteria

| Control | Findings |
|---|---|
| CC7.1 | #1, #10, #11, #12, #13, #14, #16 |
| CC8.1 | #1, #2, #10, #11, #12, #13, #14 |
| CC6.1 | #3, #6, #7, #8, #9, #15 |
| CC6.3 | #15 |
| CC6.6 | #2 |

## Methodology and limitations

- Scanners ran first. An LLM agent then read the code around each hit, judged whether it was real, and reviewed key files by hand for logic bugs scanners miss (IDOR, injection through data flow).
- A self-review pass made the agent recheck its own verdicts for false positives and duplicates before finishing.
- Compliance mapping is deterministic (no LLM), so control IDs cannot be hallucinated. The mapping table was written by hand and should be verified before a real audit.
- Results depend on the model (gemini-3.5-flash-lite). An LLM can miss issues or misjudge them, so treat this as a starting point for human review, not a final answer.
- Secret values were redacted, and key files were never sent to the LLM.
