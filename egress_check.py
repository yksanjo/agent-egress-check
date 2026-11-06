"""egress_check: a minimizing gate for outbound agent traffic.

An agent that browses, calls APIs, or fills forms will eventually try to
send user data somewhere. This library checks each outbound payload against
a per-destination disclosure policy before it leaves:

  1. Walk the payload (dicts, lists, strings) and classify what it carries:
     emails, phone numbers, API keys, bearer tokens, credit-card numbers,
     credentials in URLs, authorization headers.
  2. Match the destination host against a policy: which categories may go
     there, and what to do with the rest (block the call or redact fields).
  3. Return a Decision with findings so the caller can log exactly what
     was stopped and why.

Dependency-free, deterministic, no network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Category detectors
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
API_KEY_RE = re.compile(
    r"(?:\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"AIza[0-9A-Za-z_-]{20,})|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
URL_USERINFO_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def luhn_ok(digits: str) -> bool:
    """Luhn checksum over a string of digits."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if d < 0 or d > 9:
            return False
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cc_hits(text: str) -> List[str]:
    hits = []
    for m in CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            hits.append(m.group(0))
    return hits


def _ipv4_hits(text: str) -> List[str]:
    out = []
    for m in IPV4_RE.finditer(text):
        parts = m.group(0).split(".")
        if all(int(p) <= 255 for p in parts):
            # skip obvious version strings like 1.2.3.4 in "v1.2.3.4"?
            # keep it simple: every syntactically valid IPv4 literal counts
            out.append(m.group(0))
    return out


# (category, finder) pairs. Order matters only for deterministic findings.
_FINDERS: List[Tuple[str, Any]] = [
    ("authorization", lambda t: BEARER_RE.findall(t)),
    ("api_key", lambda t: API_KEY_RE.findall(t)),
    ("url_credential", lambda t: URL_USERINFO_RE.findall(t)),
    ("credit_card", _cc_hits),
    ("email", lambda t: EMAIL_RE.findall(t)),
    ("phone", lambda t: PHONE_RE.findall(t)),
    ("ip_address", _ipv4_hits),
]

ALL_CATEGORIES: Set[str] = {c for c, _ in _FINDERS}


def classify(text: str) -> Set[str]:
    """Return the set of data categories detected in a string."""
    found: Set[str] = set()
    if not isinstance(text, str) or not text:
        return found
    for category, finder in _FINDERS:
        if finder(text):
            found.add(category)
    return found


# ---------------------------------------------------------------------------
# Payload walking
# ---------------------------------------------------------------------------

def walk(value: Any, path: str = "$") -> Iterator[Tuple[str, str]]:
    """Yield (json-path, string) for every string leaf in a payload."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from walk(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """What one destination may receive.

    allow: categories this destination may receive.
    mode:  'block'  -> any disallowed finding fails the call
           'redact' -> disallowed string leaves are replaced
    """
    allow: frozenset
    mode: str = "block"

    def __post_init__(self) -> None:
        if self.mode not in ("block", "redact"):
            raise ValueError(f"mode must be 'block' or 'redact', got {self.mode!r}")
        unknown = set(self.allow) - ALL_CATEGORIES
        if unknown:
            raise ValueError(f"unknown categories: {sorted(unknown)}")


@dataclass
class Policy:
    """Map of host -> Rule, plus a default rule.

    A rule for 'example.com' also covers subdomains ('api.example.com').
    The most specific matching host wins. Destinations with no matching
    rule use `default`; the safe default allows nothing.
    """
    rules: Dict[str, Rule] = field(default_factory=dict)
    default: Rule = field(default_factory=lambda: Rule(frozenset(), "block"))

    def rule_for(self, host: str) -> Rule:
        host = (host or "").lower().strip(".")
        best: Optional[str] = None
        for rule_host in self.rules:
            rh = rule_host.lower().strip(".")
            if host == rh or host.endswith("." + rh):
                if best is None or len(rh) > len(best):
                    best = rh
        if best is not None:
            return self.rules[best]
        return self.default


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    path: str
    category: str
    action: str  # 'allowed', 'blocked', 'redacted'


@dataclass
class Decision:
    host: str
    allowed: bool
    findings: List[Finding]
    sanitized: Any  # payload with redactions applied (original if mode=block)

    @property
    def stopped(self) -> List[Finding]:
        return [f for f in self.findings if f.action in ("blocked", "redacted")]


REDACTED = "[redacted:{category}]"


def check(payload: Any, host: str, policy: Policy) -> Decision:
    """Check an outbound payload destined for `host` against `policy`.

    Returns a Decision. When the matched rule's mode is 'block' and any
    disallowed category is found, allowed=False and the payload must not
    be sent. When the mode is 'redact', disallowed string leaves are
    replaced in `sanitized` and allowed stays True.
    """
    rule = policy.rule_for(host)
    findings: List[Finding] = []
    blocked = False

    # collect per-path categories first
    path_categories: List[Tuple[str, Set[str]]] = []
    for path, text in walk(payload):
        cats = classify(text)
        if cats:
            path_categories.append((path, cats))
            for c in sorted(cats):
                if c in rule.allow:
                    findings.append(Finding(path, c, "allowed"))
                elif rule.mode == "redact":
                    findings.append(Finding(path, c, "redacted"))
                else:
                    findings.append(Finding(path, c, "blocked"))
                    blocked = True

    sanitized = payload
    if rule.mode == "redact" and path_categories:
        sanitized = _redact(payload, policy.rule_for(host).allow)

    return Decision(host=host, allowed=not blocked, findings=findings,
                    sanitized=sanitized)


def _redact(value: Any, allow: frozenset) -> Any:
    """Return a copy of the payload with disallowed categories replaced."""
    if isinstance(value, str):
        cats = classify(value)
        bad = cats - set(allow)
        if not bad:
            return value
        # whole-string redaction when any disallowed category is present;
        # partial masking would need span-level surgery and risks leakage
        return REDACTED.format(category=sorted(bad)[0])
    if isinstance(value, dict):
        return {k: _redact(v, allow) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, allow) for v in value]
    return value
