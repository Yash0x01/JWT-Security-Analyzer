"""
checks.py
Individual security checks for a decoded JWT. Each check function returns a
list of finding dicts: {"id": str, "severity": "HIGH"|"MEDIUM"|"LOW"|"INFO",
"issue": str, "detail": str}
"""

import time
import warnings
import jwt

SENSITIVE_FIELDS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "ssn", "social_security_number", "creditcard", "credit_card",
    "cvv", "pin", "email", "phone", "phone_number", "address",
    "dob", "date_of_birth", "private_key", "access_token", "refresh_token",
}

# Fields that are commonly (mis)used to carry authorization decisions.
# Not inherently dangerous, but worth flagging as INFO so a reviewer double
# checks the server re-validates them server-side rather than trusting them
# blindly from the token.
AUTHZ_HINT_FIELDS = {"role", "roles", "admin", "is_admin", "permissions", "scope", "scopes"}

WEAK_ALGS = {"none"}
HMAC_ALGS = {"HS256", "HS384", "HS512"}
LONG_LIVED_DAYS_THRESHOLD = 30


def _finding(fid, severity, issue, detail=""):
    return {"id": fid, "severity": severity, "issue": issue, "detail": detail}


def check_algorithm(header: dict) -> list:
    """Flag alg:none, which allows an attacker to strip the signature
    entirely and have some libraries/configs accept the token anyway."""
    findings = []
    alg = str(header.get("alg", "")).strip()

    if alg.lower() in WEAK_ALGS:
        findings.append(_finding(
            "alg_none", "HIGH",
            "Token uses alg:none (unsigned token)",
            "Any party can forge a valid-looking token with arbitrary claims. "
            "The server MUST reject alg:none explicitly and pin an allow-list of algorithms."
        ))
    elif not alg:
        findings.append(_finding(
            "alg_missing", "MEDIUM",
            "Header is missing the 'alg' claim",
            "A missing alg field is unusual and may indicate a malformed or hand-crafted token."
        ))

    return findings


def check_alg_confusion_risk(header: dict) -> list:
    """RS256/ES256/etc tokens are asymmetric (public verify key, private sign
    key). A classic vulnerability class is when a server's verifier accepts
    BOTH the asymmetric algorithm and HS256, letting an attacker sign a
    token with HS256 using the (often-public) RSA/EC public key as the HMAC
    secret. We can't detect the server's verifier config from the token
    alone, so this is an informational reminder, not a definitive finding."""
    findings = []
    alg = str(header.get("alg", ""))

    if alg in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}:
        findings.append(_finding(
            "alg_confusion_reminder", "INFO",
            f"Token uses asymmetric algorithm {alg}",
            "Verify the server's JWT library pins the expected algorithm and does not also "
            "accept HS256 using the public key as an HMAC secret (a classic 'algorithm "
            "confusion' vulnerability, CVE-2015-9235 and similar)."
        ))

    return findings


def check_exp(payload: dict) -> list:
    findings = []
    if "exp" not in payload:
        findings.append(_finding(
            "exp_missing", "MEDIUM",
            "Expiration claim (exp) is missing",
            "Tokens without an exp claim never expire, so a leaked token remains valid forever."
        ))
    else:
        try:
            exp = float(payload["exp"])
            if exp < time.time():
                findings.append(_finding(
                    "exp_past", "INFO",
                    "Token is already expired",
                    "This specific token instance has expired; a compliant verifier would reject it."
                ))
        except (TypeError, ValueError):
            findings.append(_finding(
                "exp_invalid", "MEDIUM",
                "exp claim is present but not a valid numeric timestamp",
                f"Value: {payload.get('exp')!r}"
            ))
    return findings


def check_iat_nbf(payload: dict) -> list:
    findings = []
    if "iat" not in payload:
        findings.append(_finding(
            "iat_missing", "LOW",
            "Issued-at claim (iat) is missing",
            "iat helps detect unexpectedly old tokens and supports auditing/replay analysis."
        ))
    return findings


def check_long_exp(payload: dict) -> list:
    findings = []
    if "iat" in payload and "exp" in payload:
        try:
            duration = float(payload["exp"]) - float(payload["iat"])
            days = duration / 86400
            if days > LONG_LIVED_DAYS_THRESHOLD:
                findings.append(_finding(
                    "long_lived_token", "LOW",
                    f"Token is valid for an unusually long period (~{days:.0f} days)",
                    "Long-lived access tokens increase the blast radius if leaked. "
                    "Prefer short-lived access tokens plus a separate refresh-token flow."
                ))
        except (TypeError, ValueError):
            pass
    return findings


def check_sensitive_data(payload: dict) -> list:
    findings = []
    exposed = sorted(k for k in payload if k.lower() in SENSITIVE_FIELDS)
    authz_hints = sorted(k for k in payload if k.lower() in AUTHZ_HINT_FIELDS)

    if exposed:
        findings.append(_finding(
            "sensitive_data", "MEDIUM",
            f"Potentially sensitive data in payload: {', '.join(exposed)}",
            "JWT payloads are only base64-encoded, NOT encrypted, and are trivially readable "
            "by anyone who intercepts the token (browser devtools, proxies, logs). Avoid "
            "storing PII or secrets in the payload; use an opaque reference instead."
        ))

    if authz_hints:
        findings.append(_finding(
            "authz_in_payload", "INFO",
            f"Authorization-relevant fields present in payload: {', '.join(authz_hints)}",
            "Confirm the server re-checks permissions against a trusted source rather than "
            "trusting these claims outright, especially if the token can be replayed or if "
            "signature verification is ever misconfigured."
        ))

    return findings


def check_weak_secret(token: str, header: dict, wordlist_path: str) -> list:
    """Brute-force common secrets against HMAC-signed tokens only.
    Asymmetric algorithms (RS/ES/PS*) don't use a shared secret, so this
    check is skipped for those."""
    findings = []
    alg = str(header.get("alg", ""))

    if alg not in HMAC_ALGS:
        return findings

    try:
        with open(wordlist_path) as f:
            secrets = [line.strip() for line in f if line.strip()]
    except OSError:
        return findings

    with warnings.catch_warnings():
        # Trying short/weak secrets is the entire point of this check, so the
        # library's "your key is too short" warning is expected noise here.
        warnings.simplefilter("ignore", category=jwt.exceptions.InsecureKeyLengthWarning) \
            if hasattr(jwt.exceptions, "InsecureKeyLengthWarning") else warnings.simplefilter("ignore")

        for secret in secrets:
            try:
                jwt.decode(token, secret, algorithms=[alg])
                findings.append(_finding(
                    "weak_secret", "HIGH",
                    f"Signature verifies against a common/weak secret ('{secret}')",
                    "This token can be forged by anyone with this wordlist. Rotate the signing "
                    "secret immediately and use a cryptographically random secret (32+ bytes)."
                ))
                break
            except jwt.exceptions.InvalidSignatureError:
                continue
            except Exception:
                continue

    return findings


def check_header_injection(header: dict) -> list:
    """Flag header fields historically abused for injection-style attacks
    (jku/x5u pointing to attacker-controlled keys, jwk embedding a key the
    attacker controls, kid used for path/SQL injection)."""
    findings = []

    if "jku" in header:
        findings.append(_finding(
            "jku_present", "MEDIUM",
            "Header contains 'jku' (JWK Set URL)",
            "If the verifier fetches the key from this URL without an allow-list, an attacker "
            "can point jku at a key they control and self-sign valid tokens."
        ))

    if "jwk" in header:
        findings.append(_finding(
            "jwk_present", "MEDIUM",
            "Header contains an embedded 'jwk' (public key)",
            "If the verifier trusts an embedded key instead of a pinned one, an attacker can "
            "embed their own key and self-sign valid tokens."
        ))

    if "kid" in header:
        kid = str(header["kid"])
        suspicious_chars = set("'\";|&$(){}<>`") | {".."}
        if any(c in kid for c in suspicious_chars) or "../" in kid:
            findings.append(_finding(
                "kid_suspicious", "MEDIUM",
                f"'kid' header contains suspicious characters: {kid!r}",
                "If 'kid' is used to look up a key from a file path, database, or command, "
                "unsanitized values can enable path traversal, SQL injection, or command "
                "injection in the key-lookup logic."
            ))

    return findings


def run_all_checks(token: str, header: dict, payload: dict, wordlist_path: str) -> list:
    """Run every check and return a combined, order-preserving findings list."""
    findings = []
    findings += check_algorithm(header)
    findings += check_alg_confusion_risk(header)
    findings += check_header_injection(header)
    findings += check_exp(payload)
    findings += check_iat_nbf(payload)
    findings += check_long_exp(payload)
    findings += check_sensitive_data(payload)
    findings += check_weak_secret(token, header, wordlist_path)
    return findings
