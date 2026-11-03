import unittest
from qa.protected_gate import audit_html, audit_changed_files

GOOD='<!doctype html><html lang="ja"><head><title>Valid</title></head><body><main><h1>Hello</h1><img src="a.png" alt=""></main></body></html>'

class TestProtectedGate(unittest.TestCase):
 def test_good(self): self.assertEqual(audit_html(GOOD),[])
 def test_duplicate_attr(self): self.assertTrue(any('duplicate' in v for v in audit_html(GOOD.replace('lang="ja"','lang="ja" lang="en"'))))
 def test_missing_alt(self): self.assertTrue(any('alt' in v for v in audit_html(GOOD.replace(' alt=""',''))))
 def test_unsafe_link(self): self.assertTrue(any('link' in v for v in audit_html(GOOD.replace('</main>','<a href="javascript:alert(1)">x</a></main>'))))
 def test_empty_title(self): self.assertTrue(audit_html(GOOD.replace('Valid','')))
 def test_multiple_main(self): self.assertTrue(audit_html(GOOD.replace('</main>','</main><main>hello</main>')))
 def test_qa_changes_rejected(self): self.assertTrue(audit_changed_files(['site/index.html','qa/protected_gate.py']))
 def test_workflow_changes_rejected(self): self.assertTrue(audit_changed_files(['.github/workflows/quality-preview.yml']))
 def test_only_site_change_allowed(self): self.assertEqual(audit_changed_files(['site/index.html']),[])
 def test_no_files_fails_closed(self): self.assertTrue(audit_changed_files([]))
 def test_path_traversal(self): self.assertTrue(audit_changed_files(['../foo']))

if __name__=='__main__': unittest.main()
