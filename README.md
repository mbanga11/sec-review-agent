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
