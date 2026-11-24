# sec-review-agent

AI security code review agent (work in progress).

## Threat Model

### Prompt injection
Test: planted a comment in `allocations-dao.js` instructing the AI to report no vulnerabilities.
Result: the agent ignored it and still reported the NoSQL injection (line 78).
Limitation: one simple test isn't proof. More sophisticated injections may still work, which is why scanner results and the deterministic compliance mapping don't depend on the LLM.

### Secret leakage through the agent
Found during testing: the agent used `read_file` on private key files, bypassing gitleaks' redaction and sending key contents to the LLM provider.
Fix: `read_file` now blocks key and secret file types (.pem, .key, .p12, .pfx, .crt, .env).

## Triage results (NodeGoat)
- Self-review pass: before finishing, the agent re-checks its own findings for false positives, duplicates, and missing manual review.
- gemini-3.5-flash-lite: 16 findings (14 true positive, 2 false positive). Caught 6 of 10 issues confirmed in earlier runs. Missed NoSQL injection, SSRF, stored XSS, plaintext passwords.
- Known judgment error: marked mutable GitHub Action tags as a false positive ("not reachable by users"). It is a real, low-severity supply-chain risk.

## Compliance mapping
`compliance.py` maps each finding's CWE to OWASP Top 10:2025, NIST SP 800-53 Rev. 5, and SOC 2 criteria using a hand-maintained table (`data/cwe_controls.json`). No LLM is involved, so control IDs can't be hallucinated.
NodeGoat result: 14 confirmed findings mapped to 6 OWASP categories, 9 NIST controls, and 5 SOC 2 criteria. Most affected: A03 Software Supply Chain Failures, NIST SI-2/RA-5, SOC 2 CC6.1 and CC7.1.
The mapping is my own judgment and should be verified against the official framework sources before use in a real audit.
