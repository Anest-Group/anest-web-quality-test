import base64
import unittest
from qa.trusted_pr_gate import verify, VerificationError

GOOD='<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="A safe demonstration page"><title>Good</title></head><body><main><h1>Hi</h1><img alt="" src="a.png"></main></body></html>'
SHA='a'*40
REPO='Anest-Group/anest-web-quality-test'

def mock(entries):
 def fetch(path,token):
  if path.endswith('/pulls/7'):return entries['pr']
  if '/pulls/7/files?' in path:return entries['files']
  if 'contents/site/index.html?' in path:return entries['blob']
  raise AssertionError('unexpected path '+path)
 return fetch

def entries(html=GOOD,files=None):
 return {
  'pr':{'state':'open','draft':False,'head':{'sha':SHA,'repo':{'full_name':REPO}},'base':{'ref':'main'},'changed_files':1},
  'files':files or [{'filename':'site/index.html','status':'modified'}],
  'blob':{'type':'file','encoding':'base64','content':base64.b64encode(html.encode()).decode()}
 }

class TrustedPRTests(unittest.TestCase):
 def run_verify(self, e):return verify(REPO,7,SHA,'test-token',mock(e))
 def rejects(self,e):
  with self.assertRaises(VerificationError):self.run_verify(e)
 def test_good(self):self.assertEqual(self.run_verify(entries())['result'],'PASS')
 def test_broken_html(self):self.rejects(entries(GOOD.replace(' alt=""','')))
 def test_missing_viewport_warning_is_rejected(self):
  self.rejects(entries(GOOD.replace('<meta name="viewport" content="width=device-width, initial-scale=1">','')))
 def test_missing_description_warning_is_rejected(self):
  self.rejects(entries(GOOD.replace('<meta name="description" content="A safe demonstration page">','')))
 def test_empty_label_v11_is_rejected(self):
  bad=GOOD.replace('<h1>Hi</h1>','<h1>Hi</h1><label for="email"></label><input id="email" type="email">')
  self.rejects(entries(bad))
 def test_unsafe_form_action_v11_is_rejected(self):
  bad=GOOD.replace('<h1>Hi</h1>','<h1>Hi</h1><form action="javascript:alert(1)"><label for="email">Email</label><input id="email"></form>')
  self.rejects(entries(bad))
 def test_unnamed_link_v11_is_rejected(self):
  self.rejects(entries(GOOD.replace('<h1>Hi</h1>','<h1>Hi</h1><a href="#x"></a>')))
 def test_valid_v11_html_passes(self):
  self.assertEqual(self.run_verify(entries())["result"],"PASS")
 def test_changed_policy(self):self.rejects(entries(files=[{'filename':'qa/trusted_pr_gate.py','status':'modified'}]))
 def test_changed_workflow(self):self.rejects(entries(files=[{'filename':'.github/workflows/quality-preview.yml','status':'modified'}]))
 def test_mismatched_head(self):
  e=entries();e['pr']['head']['sha']='b'*40;self.rejects(e)
 def test_draft(self):
  e=entries();e['pr']['draft']=True;self.rejects(e)
 def test_deleted_file(self):
  e=entries(files=[{'filename':'site/index.html','status':'removed'}]);self.rejects(e)
 def test_missing_file(self):
  e=entries();e['pr']['changed_files']=2;self.rejects(e)
 def test_unknown_extra_file(self):
  e=entries(files=[{'filename':'extra.txt','status':'added'}]);self.rejects(e)
 def test_other_repository(self):
  e=entries();e['pr']['head']['repo']['full_name']='someone/fork';self.rejects(e)
 def test_invalid_base(self):
  e=entries();e['pr']['base']['ref']='dev';self.rejects(e)
 def test_invalid_b64(self):
  e=entries();e['blob']['content']='not_base64';self.rejects(e)
 def test_oversize(self):self.rejects(entries('a'*500_001))
 def test_non_html_only(self):self.rejects(entries(files=[{'filename':'README.md','status':'modified'}]))

if __name__=='__main__':unittest.main()
