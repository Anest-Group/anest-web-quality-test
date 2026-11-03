#!/usr/bin/env python3
"""TEST: unauthorized checker modification. DO NOT MERGE."""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from qa.protected_gate import audit_html, audit_changed_files

API='https://api.github.com'
MAX_HTML_BYTES=500_000
MAX_FILES=500
SHA_RE=re.compile(r'^[0-9a-f]{40}$')
REPO_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')

class VerificationError(RuntimeError):
    pass

def api_get(path, token):
    req=urllib.request.Request(API+path,headers={
        'Authorization':'Bearer '+token,
        'Accept':'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28',
        'User-Agent':'anest-trusted-preview-gate',
    })
    try:
        with urllib.request.urlopen(req,timeout=20) as resp:
            if resp.status != 200: raise VerificationError('GitHub API not OK')
            data=resp.read(2_000_001)
            if len(data)>2_000_000:raise VerificationError('oversized GitHub API response')
            return json.loads(data)
    except (urllib.error.URLError,TimeoutError,ValueError) as exc:
        raise VerificationError('GitHub API request failed') from exc

def verify(repo, pr_number, head_sha, token, fetch=api_get):
    if not REPO_RE.fullmatch(repo):raise VerificationError('invalid repo')
    if not isinstance(pr_number,int) or pr_number<1:raise VerificationError('invalid PR number')
    if not SHA_RE.fullmatch(head_sha):raise VerificationError('invalid head SHA')
    pr=fetch(f'/repos/{repo}/pulls/{pr_number}',token)
    if pr.get('state')!='open' or pr.get('draft'):
        raise VerificationError('PR is not open and ready')
    if pr.get('head',{}).get('sha')!=head_sha:
        raise VerificationError('PR head does not match verified commit')
    if pr.get('base',{}).get('ref')!='main':
        raise VerificationError('unexpected base branch')
    if pr.get('head',{}).get('repo',{}).get('full_name')!=repo:
        raise VerificationError('cross-repository PR not supported in demo')
    if pr.get('changed_files',0)<1 or pr.get('changed_files',0)>MAX_FILES:
        raise VerificationError('invalid or excessive file count')
    files=[]
    for page in range(1,7):
        part=fetch(f'/repos/{repo}/pulls/{pr_number}/files?per_page=100&page={page}',token)
        if not isinstance(part,list):raise VerificationError('malformed file listing')
        files.extend(part)
        if len(part)<100:break
    if len(files)!=pr['changed_files'] or len(files)>MAX_FILES:
        raise VerificationError('incomplete changed file listing')
    names=[]
    for item in files:
        name=item.get('filename')
        if not isinstance(name,str):raise VerificationError('invalid filename')
        if item.get('status') not in ('modified','added'):
            raise VerificationError('renames or deletions need manual approval')
        names.append(name)
    bad=audit_changed_files(names)
    if bad:raise VerificationError('; '.join(bad))
    if names != ['site/index.html']:
        raise VerificationError('demo accepts only a single site/index.html change')
    qsha=urllib.parse.quote(head_sha,safe='')
    blob=fetch(f'/repos/{repo}/contents/site/index.html?ref={qsha}',token)
    if blob.get('type')!='file' or blob.get('encoding')!='base64':
        raise VerificationError('unexpected content format')
    try:
        encoded=blob['content'].replace('\n','')
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>MAX_HTML_BYTES:raise VerificationError('HTML too large')
        html=raw.decode('utf-8')
    except (KeyError,ValueError,UnicodeError) as exc:
        raise VerificationError('invalid content bytes') from exc
    errors=audit_html(html)
    if errors:raise VerificationError('; '.join(errors))
    return {'result':'PASS','head_sha':head_sha,'changed_files':names,'check':'trusted-demo-only'}

def main():
    repo=os.getenv('GITHUB_REPOSITORY','')
    token=os.getenv('GITHUB_TOKEN','')
    event_file=os.getenv('GITHUB_EVENT_PATH','')
    if not token or not event_file:
        print('HOLD: missing verified runtime context')
        return 1
    try:
        event=json.loads(Path(event_file).read_text())
        pr=event['pull_request']
        outcome=verify(repo,int(pr['number']),pr['head']['sha'],token)
        print(json.dumps(outcome,ensure_ascii=False))
        return 0
    except (VerificationError,KeyError,TypeError,ValueError,FileNotFoundError) as exc:
        print('HOLD:',exc)
        return 1

if __name__=='__main__':sys.exit(main())
