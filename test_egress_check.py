import unittest

from egress_check import (
    ALL_CATEGORIES, Decision, Finding, Policy, Rule, check, classify,
    luhn_ok, walk,
)


class TestClassify(unittest.TestCase):
    def test_email(self):
        self.assertEqual(classify("write me at sam@example.com"), {"email"})

    def test_email_needs_tld(self):
        self.assertNotIn("email", classify("user@localhost"))

    def test_phone_us_formats(self):
        self.assertIn("phone", classify("call 212-555-0147"))
        self.assertIn("phone", classify("call (212) 555-0147"))
        self.assertIn("phone", classify("call +1 212 555 0147"))

    def test_plain_number_is_not_phone(self):
        self.assertNotIn("phone", classify("order 12345 shipped"))

    def test_bearer_token(self):
        self.assertIn("authorization", classify("Bearer abcdef1234567890"))

    def test_api_key_shapes(self):
        self.assertIn("api_key", classify("key = sk-abcdefghijklmnop1234"))
        self.assertIn("api_key", classify("ghp_" + "a" * 24))
        self.assertIn("api_key", classify("AKIAIOSFODNN7EXAMPLE"))

    def test_private_key_block(self):
        self.assertIn("api_key", classify("-----BEGIN PRIVATE KEY-----"))

    def test_url_credential(self):
        self.assertIn("url_credential", classify("https://user:hunter2@db.internal/x"))

    def test_credit_card_requires_luhn(self):
        self.assertIn("credit_card", classify("card 4111 1111 1111 1111"))
        # same shape, bad checksum -> not a card
        self.assertNotIn("credit_card", classify("ref 4111 1111 1111 1112"))

    def test_ipv4_valid_and_invalid(self):
        self.assertIn("ip_address", classify("host 10.0.3.17"))
        self.assertNotIn("ip_address", classify("host 999.1.2.3"))

    def test_empty_and_nonstr(self):
        self.assertEqual(classify(""), set())
        self.assertEqual(classify(None), set())


class TestLuhn(unittest.TestCase):
    def test_known_valid(self):
        self.assertTrue(luhn_ok("4111111111111111"))
        self.assertTrue(luhn_ok("378282246310005"))  # amex test number

    def test_invalid(self):
        self.assertFalse(luhn_ok("4111111111111112"))

    def test_nondigits_rejected(self):
        self.assertFalse(luhn_ok("4111x111"))


class TestWalk(unittest.TestCase):
    def test_nested_paths(self):
        payload = {"a": {"b": ["x", {"c": "y"}]}, "n": 5}
        got = dict(walk(payload))
        self.assertEqual(got, {"$.a.b[0]": "x", "$.a.b[1].c": "y"})


class TestPolicyMatching(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(
            rules={
                "example.com": Rule(frozenset({"email"}), "block"),
                "api.example.com": Rule(frozenset({"email", "phone"}), "block"),
            },
            default=Rule(frozenset(), "block"),
        )

    def test_exact_host(self):
        self.assertIn("email", self.policy.rule_for("example.com").allow)

    def test_subdomain_inherits_parent(self):
        self.assertIn("email", self.policy.rule_for("cdn.example.com").allow)

    def test_more_specific_wins(self):
        self.assertIn("phone", self.policy.rule_for("api.example.com").allow)

    def test_unknown_host_gets_default(self):
        self.assertEqual(self.policy.rule_for("elsewhere.org").allow, frozenset())

    def test_host_case_and_dots(self):
        self.assertIn("email", self.policy.rule_for("EXAMPLE.com.").allow)

    def test_bad_category_rejected(self):
        with self.assertRaises(ValueError):
            Rule(frozenset({"dna_sequence"}))

    def test_bad_mode_rejected(self):
        with self.assertRaises(ValueError):
            Rule(frozenset(), "shred")


class TestCheckBlockMode(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(
            rules={"analytics.example.com": Rule(frozenset(), "block")},
            default=Rule(frozenset(), "block"),
        )

    def test_clean_payload_passes(self):
        d = check({"event": "page_view", "count": 3}, "analytics.example.com", self.policy)
        self.assertTrue(d.allowed)
        self.assertEqual(d.findings, [])
        self.assertEqual(d.sanitized, {"event": "page_view", "count": 3})

    def test_email_blocked(self):
        d = check({"event": "signup", "user": "sam@example.com"},
                  "analytics.example.com", self.policy)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stopped[0].category, "email")
        self.assertEqual(d.stopped[0].path, "$.user")

    def test_header_leak_blocked(self):
        d = check({"headers": {"Authorization": "Bearer tokentoken123"}},
                  "analytics.example.com", self.policy)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stopped[0].category, "authorization")

    def test_allowed_category_passes(self):
        policy = Policy(
            rules={"mail.example.com": Rule(frozenset({"email"}), "block")},
            default=Rule(frozenset(), "block"),
        )
        d = check({"to": "sam@example.com"}, "mail.example.com", policy)
        self.assertTrue(d.allowed)
        self.assertEqual(d.findings[0].action, "allowed")

    def test_multiple_findings(self):
        d = check({"user": "sam@example.com", "tel": "212-555-0147"},
                  "analytics.example.com", self.policy)
        self.assertFalse(d.allowed)
        self.assertEqual({f.category for f in d.stopped}, {"email", "phone"})

    def test_unknown_destination_blocked_by_default(self):
        d = check({"user": "sam@example.com"}, "mystery.example.net", self.policy)
        self.assertFalse(d.allowed)


class TestCheckRedactMode(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(
            rules={"logs.example.com": Rule(frozenset(), "redact")},
            default=Rule(frozenset(), "redact"),
        )

    def test_redaction_applied(self):
        d = check({"msg": "hi", "user": "sam@example.com"},
                  "logs.example.com", self.policy)
        self.assertTrue(d.allowed)  # redact mode never blocks
        self.assertEqual(d.sanitized["msg"], "hi")
        self.assertEqual(d.sanitized["user"], "[redacted:email]")
        self.assertEqual(d.findings[0].action, "redacted")

    def test_original_payload_not_mutated(self):
        payload = {"user": "sam@example.com"}
        check(payload, "logs.example.com", self.policy)
        self.assertEqual(payload["user"], "sam@example.com")

    def test_nested_redaction(self):
        d = check({"items": [{"contact": "212-555-0147"}]},
                  "logs.example.com", self.policy)
        self.assertEqual(d.sanitized["items"][0]["contact"], "[redacted:phone]")

    def test_allowed_category_survives_redaction(self):
        policy = Policy(
            rules={"logs.example.com": Rule(frozenset({"email"}), "redact")},
        )
        d = check({"user": "sam@example.com", "tel": "212-555-0147"},
                  "logs.example.com", policy)
        self.assertEqual(d.sanitized["user"], "sam@example.com")
        self.assertEqual(d.sanitized["tel"], "[redacted:phone]")

    def test_nonstring_leaves_unchanged(self):
        d = check({"n": 42, "ok": True}, "logs.example.com", self.policy)
        self.assertEqual(d.sanitized, {"n": 42, "ok": True})


class TestDecisionShape(unittest.TestCase):
    def test_decision_fields(self):
        policy = Policy(default=Rule(frozenset(), "block"))
        d = check({"a": "b"}, "x.example.com", policy)
        self.assertIsInstance(d, Decision)
        self.assertEqual(d.host, "x.example.com")
        self.assertEqual(d.stopped, [])


if __name__ == "__main__":
    unittest.main()
