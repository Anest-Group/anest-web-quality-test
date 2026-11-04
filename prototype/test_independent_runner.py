import base64
import unittest
from independent_runner import inspect_pr, Reject

REPO = 'Anest-Group/anest-web-quality-test'
SHA = 'a' * 40

class TestIndependentRunner(unittest.TestCase):
    def setUp(self):
        self.event = {'number': 11, 'repository': {'full_name': REPO}, 'pull_request': {'head': {'sha': SHA}}}
        self.pr = {'number': 11, 'state': 'open', 'draft': False, 'head': {'sha': SHA, 'repo': {'full_name': REPO}},
                   'base': {'repo': {'full_name': REPO}, 'ref': 'main'}, 'changed_files': 1}
        self.files = [{'filename': 'site/index.html', 'status': 'modified'}]
        self.content = {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(b'<html>valid</html>').decode()}
        self.calls = []

    def execute(self, audit=None):
        def content(repo, name, sha):
            self.calls.append((repo, name, sha))
            return self.content
        return inspect_pr(self.event, lambda *_: self.pr, lambda *_: self.files,
                          content, audit if audit is not None else lambda html: [], REPO)

    def test_pass(self):
        result = self.execute()
        self.assertEqual(result['sha'], SHA)
        self.assertEqual(self.calls, [(REPO, 'site/index.html', SHA)])
    def test_wrong_repo(self):
        self.event['repository']['full_name'] = 'attacker/fork'
        self.assertRaises(Reject, self.execute)
    def test_stale_sha(self):
        self.pr['head']['sha'] = 'b' * 40
        self.assertRaises(Reject, self.execute)
    def test_wrong_base(self):
        self.pr['base']['ref'] = 'other'
        self.assertRaises(Reject, self.execute)
    def test_draft(self):
        self.pr['draft'] = True
        self.assertRaises(Reject, self.execute)
    def test_closed(self):
        self.pr['state'] = 'closed'
        self.assertRaises(Reject, self.execute)
    def test_other_pr_number(self):
        self.pr['number'] = 12
        self.assertRaises(Reject, self.execute)
    def test_wrong_pr_head_repo(self):
        self.pr['head']['repo']['full_name'] = 'attacker/fork'
        self.assertRaises(Reject, self.execute)
    def test_changed_gate_code(self):
        self.files[0]['filename'] = 'qa/trusted_pr_gate.py'
        self.assertRaises(Reject, self.execute)
    def test_extra_files(self):
        self.pr['changed_files'] = 2
        self.assertRaises(Reject, self.execute)
    def test_deleted_html(self):
        self.files[0]['status'] = 'removed'
        self.assertRaises(Reject, self.execute)
    def test_invalid_base64(self):
        self.content['content'] = 'not-base64!'
        self.assertRaises(Reject, self.execute)
    def test_oversize(self):
        self.content['content'] = base64.b64encode(b'a' * 500001).decode()
        self.assertRaises(Reject, self.execute)
    def test_invalid_utf8(self):
        self.content['content'] = base64.b64encode(bytes([255])).decode()
        self.assertRaises(Reject, self.execute)
    def test_auditor_findings(self):
        self.assertRaises(Reject, self.execute, lambda _: ['unsafe'])
    def test_nonlist_audit_result(self):
        self.assertRaises(Reject, self.execute, lambda _: True)
    def test_invalid_sha(self):
        self.event['pull_request']['head']['sha'] = 'not-a-sha'
        self.assertRaises(Reject, self.execute)
    def test_bool_pr_number(self):
        self.event['number'] = True
        self.assertRaises(Reject, self.execute)

if __name__ == '__main__':
    unittest.main()
