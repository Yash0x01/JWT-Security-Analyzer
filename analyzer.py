"""
analyzer.py
Orchestrates decoding + checks, computes an overall risk rating, and attaches
remediation advice to each finding.
"""

from utils import decode_token, TokenDecodeError
from checks import run_all_checks

SEVERITY_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

REMEDIATIONS = {
    "alg_none": "Reject alg:none server-side; explicitly pin an algorithm allow-list when verifying (e.g. algorithms=['HS256']).",
    "alg_missing": "Ensure tokens are generated with a valid, explicit 'alg' header.",
    "alg_confusion_reminder": "Pin the exact expected algorithm in your verifier; never accept both an asymmetric algorithm and HS256 for the same key material.",
    "exp_missing": "Always set an 'exp' claim with a short, appropriate lifetime.",
    "exp_past": "No action needed on this token; ensure your verifier checks exp on every request.",
    "exp_invalid": "Set exp to a numeric UNIX timestamp (seconds since epoch).",
    "iat_missing": "Include an 'iat' claim for auditability and replay-window analysis.",
    "long_lived_token": "Shorten token lifetime; use refresh tokens for long-lived sessions instead of long-lived access tokens.",
    "sensitive_data": "Remove PII/secrets from the payload; store an opaque user/session ID and look up sensitive data server-side.",
    "authz_in_payload": "Re-validate authorization server-side against a trusted source rather than trusting claims in the token alone.",
    "weak_secret": "Rotate the signing secret; use a cryptographically random secret of at least 32 bytes (e.g. secrets.token_bytes(32)).",
    "jku_present": "Only accept jku URLs from a strict allow-list, or avoid jku entirely and pin keys server-side.",
    "jwk_present": "Ignore embedded jwk headers; verify only against server-pinned keys.",
    "kid_suspicious": "Sanitize/allow-list 'kid' values before using them to look up keys; never build file paths or queries from raw kid input.",
}

DEFAULT_REMEDIATION = "Review this finding against OWASP JWT security guidance."


def calculate_risk(findings: list) -> str:
    score = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    if score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "INFO"


def analyze(token: str, wordlist_path: str = "common_secrets.txt") -> dict:
    """
    Run the full analysis pipeline on a raw JWT string.
    Returns a dict: {header, payload, findings, risk} or raises TokenDecodeError.
    """
    header, payload, _signature = decode_token(token)
    findings = run_all_checks(token, header, payload, wordlist_path)

    for f in findings:
        f["remediation"] = REMEDIATIONS.get(f["id"], DEFAULT_REMEDIATION)

    risk = calculate_risk(findings)

    return {
        "header": header,
        "payload": payload,
        "findings": findings,
        "risk": risk,
    }
