# ============================================================
# OWASP Security — services/validator.py
# Input validation & sanitization for URLs and file hashes.
# OWASP A03: Injection | OWASP A01: Broken Access Control
# ============================================================

import re
import bleach
import validators
from loguru import logger
from config import settings


class ValidationError(ValueError):
    """Raised when user input fails validation checks."""
    pass


# ── Regex: only hex characters in a hash ─────────────────────
_HASH_REGEX = re.compile(r"^[a-fA-F0-9]+$")

# ── Characters explicitly blocked in URLs ────────────────────
_DANGEROUS_URL_CHARS = re.compile(r"[<>\"'`;\\]")


def validate_url(raw_url: str) -> str:
    """Validate and sanitize a URL string.

    Steps:
      1. Strip whitespace.
      2. Check length (OWASP A03 — long inputs can signal attacks).
      3. Block dangerous characters that could enable XSS/injection.
      4. Verify it is a well-formed http/https URL.
      5. Bleach-clean for any residual HTML entities.

    Returns the cleaned URL string on success.
    Raises ValidationError on failure.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValidationError("URL must be a non-empty string.")

    url = raw_url.strip()

    # ── Length guard ──────────────────────────────────────────
    if len(url) > settings.MAX_URL_LENGTH:
        raise ValidationError(
            f"URL exceeds maximum allowed length of {settings.MAX_URL_LENGTH} chars."
        )

    # ── Reject dangerous characters (XSS / injection) ────────
    if _DANGEROUS_URL_CHARS.search(url):
        logger.warning(f"[VALIDATOR] Dangerous characters in URL: {url[:80]}")
        raise ValidationError("URL contains invalid or dangerous characters.")

    # ── Must start with http/https ────────────────────────────
    if not url.startswith(("http://", "https://")):
        raise ValidationError("URL must start with http:// or https://")

    # ── validators library does strict RFC checking ───────────
    if not validators.url(url):
        raise ValidationError("URL format is invalid.")

    # ── Sanitize any HTML that might have slipped through ─────
    url = bleach.clean(url, tags=[], strip=True)

    logger.debug(f"[VALIDATOR] URL validated: {url[:80]}")
    return url


def validate_hash(raw_hash: str) -> str:
    """Validate a file hash (MD5 / SHA-1 / SHA-256).

    Steps:
      1. Strip whitespace and lowercase.
      2. Check allowed lengths (32, 40, or 64 hex chars).
      3. Confirm only hexadecimal characters are present.

    Returns the lowercased hash on success.
    Raises ValidationError on failure.
    """
    if not raw_hash or not isinstance(raw_hash, str):
        raise ValidationError("Hash must be a non-empty string.")

    h = raw_hash.strip().lower()

    # ── Length must match MD5 / SHA-1 / SHA-256 ───────────────
    if len(h) not in settings.ALLOWED_HASH_LENGTHS:
        raise ValidationError(
            f"Hash must be MD5 (32), SHA-1 (40), or SHA-256 (64) hex characters. "
            f"Got {len(h)} characters."
        )

    # ── Only hex digits allowed ───────────────────────────────
    if not _HASH_REGEX.fullmatch(h):
        raise ValidationError("Hash must contain only hexadecimal characters (0-9, a-f).")

    logger.debug(f"[VALIDATOR] Hash validated: {h}")
    return h
