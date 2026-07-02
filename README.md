# JWT Security Analyzer

A command-line tool that decodes a JSON Web Token and analyzes it for common
security weaknesses: `alg:none`, weak/brute-forceable HMAC secrets, missing
or excessive expiration, sensitive data in the payload, header injection
vectors (`jku`, `jwk`, `kid`), and algorithm-confusion risk. Produces a
risk-scored report with remediation guidance.

> **Scope note:** this tool only *inspects* tokens you already have (decoding
> and, for HS* tokens, testing against a small local wordlist of known-weak
> secrets). It does not attack a live server, intercept traffic, or bypass
> authentication anywhere. Use it only against tokens you own or are
> authorized to test.

## Install

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python jwt_analyzer.py <token>
python jwt_analyzer.py --file token.txt
echo "<token>" | python jwt_analyzer.py
python jwt_analyzer.py <token> --json
python jwt_analyzer.py <token> --wordlist my_wordlist.txt
python jwt_analyzer.py <token> --no-color
```

Exit codes: `0` = no HIGH-risk findings, `1` = HIGH risk, `2` = token could
not be parsed. This makes it easy to drop into a CI pipeline.

## What it checks

| Check | Severity | Notes |
|---|---|---|
| `alg: none` | HIGH | Unsigned token — anyone can forge claims |
| Weak/common HMAC secret | HIGH | Brute-forced against `common_secrets.txt` for HS256/384/512 only |
| Suspicious `kid` header | MEDIUM | Chars suggesting path traversal / SQLi / command injection |
| `jku` / `jwk` in header | MEDIUM | Verifier may trust an attacker-supplied key source |
| Missing `exp` | MEDIUM | Token never expires |
| Sensitive fields in payload | MEDIUM | Payload is base64, not encrypted — anyone can read it |
| Long-lived token (>30 days) | LOW | Increases blast radius of a leaked token |
| Missing `iat` | LOW | Hurts auditability |
| Asymmetric algorithm in use | INFO | Reminder to check for HS256/RS256 confusion (CVE-2015-9235-class) |
| Authorization fields present | INFO | Reminder that server must still re-check permissions |

Overall risk = HIGH / MEDIUM / LOW / INFO based on a weighted sum of finding
severities (HIGH=3, MEDIUM=2, LOW=1, INFO=0; ≥6 → HIGH, ≥3 → MEDIUM, ≥1 → LOW).

## Project structure

```
jwt-security-analyzer/
├── jwt_analyzer.py     # CLI entry point, report/JSON output
├── analyzer.py         # Orchestrates checks, risk scoring, remediation text
├── checks.py           # Individual security checks
├── utils.py            # Unverified decode helpers
├── common_secrets.txt  # Wordlist for the weak-secret check
├── requirements.txt
└── sample_tokens/      # Example tokens for trying the tool out
```

## Example

```
$ python jwt_analyzer.py "$(cat sample_tokens/weak_secret_and_pii.txt)"
============================================================
JWT SECURITY ANALYSIS REPORT
============================================================

Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "12345",
  "email": "admin@example.com",
  "role": "admin"
}

Findings: (5)
  [MEDIUM] Expiration claim (exp) is missing
  [LOW] Issued-at claim (iat) is missing
  [MEDIUM] Potentially sensitive data in payload: email
  [INFO] Authorization-relevant fields present in payload: role
  [HIGH] Signature verifies against a common/weak secret ('secret')

Overall Risk: HIGH

Recommendations:
  - Always set an 'exp' claim with a short, appropriate lifetime.
  - Include an 'iat' claim for auditability and replay-window analysis.
  - Remove PII/secrets from the payload; store an opaque user/session ID and look up sensitive data server-side.
  - Re-validate authorization server-side against a trusted source rather than trusting claims in the token alone.
  - Rotate the signing secret; use a cryptographically random secret of at least 32 bytes (e.g. secrets.token_bytes(32)).
```
<!--
## Possible extensions

- Flask/HTML report export
- OWASP Top 10 / ASVS mapping per finding
- Support for testing `jku`/`x5u` allow-list bypass scenarios in a lab setup
- Docker image + REST API wrapper
-->
- CI GitHub Action that fails a build on HIGH-risk tokens in test fixtures

## Disclaimer

For educational and authorized security-testing use only. Only analyze
tokens you own or have explicit permission to test.
