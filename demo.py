"""Synthetic demo: an agent about to send three outbound calls.

All hosts, addresses, and tokens below are fictional.
"""

from egress_check import Policy, Rule, check

policy = Policy(
    rules={
        # the product's own API may receive the user's email (signup flow)
        "api.example-app.com": Rule(frozenset({"email"}), "block"),
        # product analytics gets nothing identifying; strip what sneaks in
        "analytics.example-app.com": Rule(frozenset(), "redact"),
        # everything else defaults to: allow nothing, block the call
    },
    default=Rule(frozenset(), "block"),
)

calls = [
    ("api.example-app.com", {
        "op": "create_account",
        "email": "jane@example-user.com",
    }),
    ("analytics.example-app.com", {
        "event": "signup_complete",
        "user_email": "jane@example-user.com",   # copied in by mistake
        "headers": {"Authorization": "Bearer synth-token-abc123"},
    }),
    ("webhook.randohost.net", {
        "note": "new signup",
        "card_on_file": "4111 1111 1111 1111",
    }),
]

for host, payload in calls:
    d = check(payload, host, policy)
    verdict = "SEND" if d.allowed else "STOP"
    print(f"{verdict:4}  -> {host}")
    for f in d.findings:
        print(f"      {f.action:8} {f.category:13} at {f.path}")
    if d.allowed and d.sanitized != payload:
        print(f"      sent as: {d.sanitized}")
    print()

print("The analytics call still went out, minus the email and auth header.")
print("The unknown webhook host lost the whole call: no rule, default deny.")
