"""Contract regressions over actual HTTP exchanges and final SQL evidence."""
import unittest

from run_demo import expense, run_suite


class HTTPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_suite()
        cls.cases = {case["id"]: case for case in cls.report["cases"]}

    def test_authorized_positive_control(self):
        case = self.cases["H01"]
        self.assertEqual(case["http_exchanges"][0]["response"]["status"], 201)
        self.assertEqual(expense(case["after"])["version"], 1)
        self.assertEqual(case["after"]["audit"][-1]["outcome"], "committed")

    def test_403_does_not_hide_state_effect_in_fixed_version(self):
        bad, good = self.cases["H03"], self.cases["H02"]
        self.assertEqual(bad["http_exchanges"][-1]["response"]["status"], 403)
        self.assertNotEqual(bad["before"]["expenses"], bad["after"]["expenses"])
        self.assertEqual(bad["observed_verdict"], "FAIL")
        self.assertEqual(good["before"]["expenses"], good["after"]["expenses"])
        self.assertEqual(good["observed_verdict"], "PASS")

    def test_reauthorization_precedes_receipt_lookup(self):
        good, bad = self.cases["H05"], self.cases["H06"]
        self.assertEqual(good["http_exchanges"][-1]["response"]["status"], 403)
        self.assertEqual(good["after"]["audit"][-1]["outcome"], "authorization_denied")
        self.assertEqual(bad["http_exchanges"][-1]["response"]["status"], 200)
        self.assertEqual(bad["observed_verdict"], "FAIL")

    def test_scope_and_role_denials_preserve_protected_state(self):
        for identity in ("H07", "H08", "H13"):
            with self.subTest(case=identity):
                case = self.cases[identity]
                self.assertEqual(case["http_exchanges"][0]["response"]["status"], 403)
                self.assertEqual(case["before"]["expenses"], case["after"]["expenses"])
                self.assertEqual(case["before"]["grants"], case["after"]["grants"])

    def test_concurrent_same_key_commits_only_once(self):
        case = self.cases["H09"]
        statuses = [call["response"]["status"] for call in case["http_exchanges"]]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 11)
        self.assertEqual(len({r["request"]["request_id"] for r in case["http_exchanges"]}), 12)
        self.assertEqual(expense(case["after"])["version"], 1)
        self.assertEqual(len(case["after"]["receipts"]), 1)

    def test_concurrent_different_keys_still_commit_only_once(self):
        case = self.cases["H10"]
        statuses = [call["response"]["status"] for call in case["http_exchanges"]]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 11)
        self.assertEqual(expense(case["after"])["version"], 1)

    def test_restart_preserves_receipt_and_business_state(self):
        case = self.cases["H11"]
        self.assertEqual(case["http_exchanges"][-1]["response"]["status"], 200)
        self.assertTrue(case["http_exchanges"][-1]["response"]["body"]["replayed"])
        self.assertEqual(case["snapshot_after_shutdown"]["expenses"], case["after"]["expenses"])
        self.assertEqual(case["snapshot_after_shutdown"]["receipts"], case["after"]["receipts"])

    def test_unknown_identity_has_no_database_effect(self):
        case = self.cases["H12"]
        self.assertEqual(case["http_exchanges"][0]["response"]["status"], 401)
        self.assertEqual(case["before"], case["after"])

    def test_reused_request_identifier_is_not_a_new_attempt(self):
        case = self.cases["H14"]
        self.assertEqual(case["http_exchanges"][-1]["response"]["status"], 409)
        self.assertEqual(len(case["after"]["requests"]), 1)
        self.assertEqual(len(case["after"]["audit"]), 1)

    def test_fixture_outcomes_and_observation_contracts(self):
        for case in self.report["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["observed_verdict"], case["expected_verdict"])
                for call in case["http_exchanges"]:
                    self.assertEqual(call["response"]["body"]["request_id"], call["request"]["request_id"])
        self.assertEqual(self.report["summary"]["http_requests"], 45)


if __name__ == "__main__":
    unittest.main()
