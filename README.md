# agent-egress-check

A minimizing gate for outbound agent traffic, in dependency-free Python.

An agent that browses, calls APIs, or fills forms will eventually try to
send user data somewhere it was never meant to go: the email address pasted
into an analytics event, the Authorization header copied into a third-party
request, the card number included in a webhook body. `egress_check` sits
between the agent and the network and answers one question per call:
**does this destination get to receive what this payload actually carries?**

## How it works

1. **Classify.** The payload is walked leaf by leaf (dicts, lists, strings)
   and each string is checked by a detector set: emails, US phone numbers,
   bearer tokens, common API-key shapes, credit-card numbers (Luhn-verified),
   credentials embedded in URLs, and IPv4 literals.
2. **Match.** The destination host is matched against a policy. A rule for
   `example.com` covers its subdomains; the most specific rule wins; hosts
   with no rule fall through to the default (deny everything, block the call,
   unless you configure otherwise).
3. **Decide.** Each rule picks a mode:
   - `block` - any disallowed category fails the call; the agent must not send it.
   - `redact` - disallowed string leaves are replaced with
     `[redacted:<category>]` in a sanitized copy, and the call may proceed.

Every check returns a `Decision` with per-field findings (`path`, `category`,
`action`) so the caller can log exactly what was stopped and why.

## Usage

```python
from egress_check import Policy, Rule, check

policy = Policy(
    rules={
        "api.example-app.com": Rule(frozenset({"email"}), "block"),
        "analytics.example-app.com": Rule(frozenset(), "redact"),
    },
    default=Rule(frozenset(), "block"),  # unknown hosts get nothing
)

d = check({"event": "signup", "user_email": "jane@example-user.com"},
          "analytics.example-app.com", policy)

if not d.allowed:
    raise RuntimeError(f"egress blocked: {d.stopped}")
send(d.sanitized)  # your HTTP layer
```

## Demo and tests

```
python3 demo.py                    # scripted scenario, no network
python3 -m unittest test_egress_check -v   # 34 tests
```

The demo shows three calls: a clean signup to the app's own API (sent), an
analytics event carrying a stray email and auth header (sent, both fields
redacted), and a card number headed to an unknown webhook host (blocked).

## Honest limits

- **Heuristics, not proof.** The detectors are regexes plus a Luhn check.
  They catch common shapes and miss obfuscated, encoded, split, or unusual
  ones. A clean result does not prove a payload is safe; a blocked result
  tells you exactly which pattern fired.
- **No name or free-text detection.** People's names, street addresses, and
  prose secrets are not reliably detectable by pattern and are not claimed
  here. Detected categories: `email`, `phone`, `authorization`, `api_key`,
  `url_credential`, `credit_card`, `ip_address`.
- **Whole-leaf redaction.** A string containing any disallowed category is
  replaced entirely; this library does not do partial masking inside a
  string. Safer than surgical edits, coarser than ideal.
- **The gate is only as good as its placement.** It checks payloads you
  route through it. Code with direct network access bypasses it.
- **Policy is yours to write.** Defaults deny, but deciding which service
  legitimately needs the user's email is a product decision this library
  cannot make for you.
- US-centric phone pattern; other regions need their own detector.

## License

MIT. See [LICENSE](LICENSE).
