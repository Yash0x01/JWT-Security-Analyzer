"""
utils.py
Helper functions for decoding JWTs without verification, and low-level
base64url handling used by structural checks.
"""

import base64
import json
import jwt


class TokenDecodeError(Exception):
    """Raised when a string cannot be parsed as a structurally valid JWT."""
    pass


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, padding it out as needed."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_token(token: str):
    """
    Decode a JWT's header and payload WITHOUT verifying the signature.
    This is intentional and required for security analysis: we need to be
    able to inspect tokens whose secret/key we don't have.

    Returns (header: dict, payload: dict, signature_segment: str).
    Raises TokenDecodeError if the token is malformed.
    """
    token = token.strip()

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenDecodeError(
            f"Expected 3 dot-separated segments (header.payload.signature), got {len(parts)}"
        )

    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        raise TokenDecodeError(f"Could not parse header: {e}")

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError as e:
        # Payload may not be a JSON object (rare, but handle gracefully)
        try:
            raw = _b64url_decode(parts[1])
            payload = json.loads(raw)
        except Exception:
            raise TokenDecodeError(f"Could not parse payload: {e}")
    except Exception as e:
        raise TokenDecodeError(f"Could not parse payload: {e}")

    signature_segment = parts[2]

    return header, payload, signature_segment


def get_signing_input(token: str) -> bytes:
    """Return the 'header.payload' bytes that are actually signed."""
    header_b64, payload_b64, _ = token.strip().split(".")
    return f"{header_b64}.{payload_b64}".encode("ascii")
