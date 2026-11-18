"""Content-Security-Policy builder.

The policy produced here is deny-by-default:

* ``default-src 'none'`` unless the caller supplies valid sources;
* ``unsafe-inline`` / ``unsafe-eval``, wildcards, ``data:``, ``blob:`` and
  plain ``http:`` are always rejected;
* script sources are restricted to an allowlist of keywords, nonces,
  hashes and ``https://`` origins;
* nonces come from :mod:`secrets` (high entropy, unpredictable);
* ``object-src`` and ``frame-ancestors`` are locked to ``'none'``;
* the report endpoint is fixed by the server, never taken from input;
* duplicate directives/sources are collapsed and ``'none'`` wins over any
  other source in the same directive;
* merging policies always yields the stricter result.
"""

from __future__ import annotations

import re
import secrets

__all__ = [
    "REPORT_URI",
    "build_csp",
    "validate_source",
    "nonce",
    "is_unsafe",
    "merge_policy",
]

# Server-controlled reporting endpoint. Callers cannot override this: a
# user-supplied report-uri would let an attacker exfiltrate data via the
# browser's violation reports.
REPORT_URI = "/csp-report"

# 24 random bytes -> 32 URL-safe characters (~192 bits of entropy).
NONCE_BYTES = 24

_UNSAFE_SCHEMES = (
    "data:",
    "blob:",
    "javascript:",
    "vbscript:",
    "file:",
    "filesystem:",
)

_KEYWORD_SOURCES = {"self", "none", "strict-dynamic", "report-sample"}

# Directives that take no value; an empty token list is valid for them.
_VALUE_LESS_DIRECTIVES = {
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "sandbox",
}

# Directives that are forced by this builder and cannot be overridden.
_LOCKED_DIRECTIVES = {"object-src", "frame-ancestors"}

_DIRECTIVE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_NONCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/=_-]{16,}'$")
_HASH_RE = re.compile(r"^'sha(?:256|384|512)-[A-Za-z0-9+/=_-]+'$")
_HTTPS_RE = re.compile(r"^https://[^\s;,'\"()*]+$")


def nonce(nbytes: int = NONCE_BYTES) -> str:
    """Return a fresh, unpredictable CSP nonce.

    Uses :mod:`secrets` (CSPRNG), never a timestamp or counter, so the value
    cannot be predicted by an attacker.
    """

    if nbytes < 16:
        raise ValueError("nonce must be at least 16 bytes")
    return secrets.token_urlsafe(nbytes)


def is_unsafe(source) -> bool:
    """Return ``True`` when *source* is unsafe or malformed."""

    if not isinstance(source, str):
        return True

    value = source.strip()
    if not value:
        return True

    lowered = value.lower()

    # Reject CR/LF and CSP separators to prevent header/directive injection.
    if any(ch in value for ch in "\r\n;,"):
        return True

    # Wildcards and inline/eval escapes.
    if "*" in lowered:
        return True
    if "unsafe" in lowered:
        return True

    # Dangerous or downgrade-prone schemes.
    if lowered.startswith(_UNSAFE_SCHEMES):
        return True
    if lowered.startswith("http:"):
        return True
    if lowered.startswith("//"):
        return True

    return False


def validate_source(source) -> bool:
    """Validate a single CSP source expression.

    Only these are accepted:

    * the keywords ``'self'``, ``'none'``, ``'strict-dynamic'``;
    * ``'nonce-<value>'`` / ``'sha256|384|512-<value>'``;
    * explicit ``https://`` origins.

    Everything else (``*``, ``'unsafe-inline'``, ``'unsafe-eval'``,
    ``data:``, ``blob:``, ``http://``, empty strings, ...) is rejected.
    """

    if is_unsafe(source):
        return False

    value = source.strip()
    lowered = value.lower()

    if lowered in {"'self'", "self", "'none'", "none", "'strict-dynamic'", "strict-dynamic"}:
        return True

    if _NONCE_RE.match(value) or _HASH_RE.match(value):
        return True

    if lowered.startswith("https://"):
        return bool(_HTTPS_RE.match(value))

    return False


def _iter_sources(value):
    """Yield raw source strings from a directive value."""

    if value is None:
        return
    if isinstance(value, str):
        for item in value.split():
            yield item
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if isinstance(item, str):
                yield item
        return
    # Unknown types are ignored rather than stringified.


def _canon(token: str) -> str:
    """Canonical form used only for comparisons/deduplication."""

    value = token.strip().lower()
    if value in ("'self'", "self"):
        return "self"
    if value in ("'none'", "none"):
        return "none"
    if value in ("'strict-dynamic'", "strict-dynamic"):
        return "strict-dynamic"
    return value


def _quote_keyword(token: str) -> str:
    """Render keyword sources in their canonical quoted CSP form."""

    if token.lower() in _KEYWORD_SOURCES:
        return "'{}'".format(token.lower())
    return token


def _dedupe(tokens):
    seen = set()
    result = []
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        result.append(token)
    return result


def _sanitise_sources(value, get_nonce):
    """Return validated, deduplicated sources for a directive.

    ``'none'`` is terminal: per the CSP grammar it may not be combined with
    other sources, so it collapses the directive to a deny.
    """

    tokens = []
    for raw in _iter_sources(value):
        item = raw.strip()
        if not item:
            continue

        # Sentinel understood by this builder, replaced by a fresh nonce.
        if item.lower() in ("nonce", "'nonce'"):
            item = "'nonce-{}'".format(get_nonce())
        else:
            item = _quote_keyword(item)

        if not validate_source(item):
            continue
        tokens.append(item)

    tokens = _dedupe(tokens)
    if any(_canon(token) == "none" for token in tokens):
        return ["'none'"]
    return tokens


def build_csp(policy=None, **kwargs) -> str:
    """Build a hardened CSP header string.

    ``policy`` (and any keyword directives) map directive names to a source
    string or list of source strings. Unsafe sources are dropped; if a
    directive is left with nothing valid it is denied with ``'none'``.
    ``report-uri`` is always set to :data:`REPORT_URI`, and ``object-src`` /
    ``frame-ancestors`` are always locked to ``'none'``.
    """

    raw = {}
    if policy is not None:
        if not isinstance(policy, dict):
            raise TypeError("policy must be a mapping")
        raw.update(policy)
    raw.update(kwargs)

    held_nonce = {}

    def get_nonce():
        if "value" not in held_nonce:
            held_nonce["value"] = nonce()
        return held_nonce["value"]

    directives = {}

    for name, value in raw.items():
        if not isinstance(name, str):
            continue

        directive = name.strip().lower()
        if not _DIRECTIVE_RE.match(directive):
            continue

        # Reporting endpoints are fixed by the server, and these two
        # directives are forced below.
        if directive in ("report-uri", "report-to"):
            continue
        if directive in _LOCKED_DIRECTIVES:
            continue

        tokens = _sanitise_sources(value, get_nonce)
        if not tokens and directive not in _VALUE_LESS_DIRECTIVES:
            tokens = ["'none'"]
        directives[directive] = tokens

    # default-src first, denying by default.
    ordered = {"default-src": directives.pop("default-src", ["'none'"])}
    for name, tokens in directives.items():
        ordered[name] = tokens

    # Forced hardening directives.
    ordered["object-src"] = ["'none'"]
    ordered["frame-ancestors"] = ["'none'"]
    ordered["report-uri"] = [REPORT_URI]

    parts = []
    for name, tokens in ordered.items():
        if tokens:
            parts.append("{} {}".format(name, " ".join(tokens)))
        else:
            parts.append(name)
    return "; ".join(parts)


def _stricter(first, second):
    """Combine two token lists for the same directive, keeping the stricter."""

    canon_first = {_canon(token) for token in first}
    canon_second = {_canon(token) for token in second}

    # Deny always wins.
    if "none" in canon_first or "none" in canon_second:
        return ["none"]

    # Nonces are per-response and additive; keep the union.
    nonces = []
    for token in list(first) + list(second):
        canon = _canon(token)
        if canon.startswith("nonce-") and token not in nonces:
            nonces.append(token)

    # For every other source, only what both policies allow survives.
    intersection = []
    seen = set()
    for token in first:
        canon = _canon(token)
        if canon.startswith("nonce-"):
            continue
        if canon in canon_second and canon not in seen:
            seen.add(canon)
            intersection.append(token)

    result = _dedupe(intersection + nonces)
    return result or ["none"]


def merge_policy(*policies):
    """Merge CSP policies together, always keeping the stricter result.

    Every directive is validated (unsafe sources are dropped) and
    deduplicated. When both policies define a directive, the intersection of
    their sources is used; ``'none'`` in either policy wins. Duplicate
    directives are therefore never allowed to weaken an earlier policy.
    """

    merged = {}

    for policy in policies:
        if not policy:
            continue
        if not isinstance(policy, dict):
            raise TypeError("policy must be a mapping")

        for name, value in policy.items():
            if not isinstance(name, str):
                continue

            directive = name.strip().lower()
            if not _DIRECTIVE_RE.match(directive):
                continue

            tokens = []
            for raw in _iter_sources(value):
                token = raw.strip()
                if token and validate_source(token):
                    tokens.append(token)
            tokens = _dedupe(tokens)

            if directive in merged:
                merged[directive] = _stricter(merged[directive], tokens or ["none"])
            else:
                merged[directive] = tokens or ["none"]

    return merged
