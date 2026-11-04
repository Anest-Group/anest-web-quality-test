import unittest
from identity_gate import GateRejected, validate_pr_identity
R = "Anest-Group/anest-web-quality-test"
S = "a" * 40

class TestBinding(unittest.TestCase):
    def setUp(self):
        self.event = {"repository": {"full_name": R}, "number": 8,
                      "pull_request": {"head": {"sha": S}}}
        self.fetched = {"number": 8, "head": {"sha": S, "repo": {"full_name": R}},
                        "base": {"repo": {"full_name": R}, "ref": "main"},
                        "state": "open", "draft": False}
    def test_pass(self):
        self.assertEqual(validate_pr_identity(self.event, self.fetched, R)["head_sha"], S)
    def test_stale_sha_rejected(self):
        self.fetched["head"]["sha"] = "b" * 40
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_changed_target_rejected(self):
        self.fetched["base"]["ref"] = "unsafe"
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_cross_repo_rejected(self):
        self.fetched["head"]["repo"]["full_name"] = "attacker/another"
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_draft_rejected(self):
        self.fetched["draft"] = True
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_malformed_rejected(self):
        self.event["pull_request"] = {}
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_wrong_number_rejected(self):
        self.fetched["number"] = 9
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)
    def test_unexpected_repo_rejected(self):
        self.event["repository"]["full_name"] = "other/repo"
        self.assertRaises(GateRejected, validate_pr_identity, self.event, self.fetched, R)

if __name__ == "__main__":
    unittest.main()
