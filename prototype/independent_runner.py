"""Proof-of-concept gate; executes only trusted caller-provided auditor."""
import base64
import binascii
import re

SHA_RE = re.compile(r'[0-9a-f]{40}\Z')
MAX_HTML = 500_000

class Reject(ValueError):
    pass

def inspect_pr(event, get_pr, get_files, get_content, audit, expected_repo):
    """All API responses must come from an authenticated, trusted caller.

    The independent check issuer and its credentials are outside this prototype.
    """
    if not isinstance(event, dict):
        raise Reject('invalid event')
    try:
        pr_number = event['number']
        event_repo = event['repository']['full_name']
        event_sha = event['pull_request']['head']['sha']
    except (KeyError, TypeError) as exc:
        raise Reject('missing identity') from exc
    if not isinstance(expected_repo, str) or event_repo != expected_repo:
        raise Reject('wrong repository')
    if type(pr_number) is not int or pr_number < 1 or not isinstance(event_sha, str) or not SHA_RE.fullmatch(event_sha):
        raise Reject('invalid PR identity')
    pr = get_pr(expected_repo, pr_number)
    try:
        if (pr['number'] != pr_number or pr['state'] != 'open' or pr['draft'] is not False
            or pr['head']['sha'] != event_sha or pr['head']['repo']['full_name'] != expected_repo
            or pr['base']['repo']['full_name'] != expected_repo or pr['base']['ref'] != 'main'):
            raise Reject('PR metadata mismatch')
        count = pr['changed_files']
    except (KeyError, TypeError) as exc:
        raise Reject('bad metadata') from exc
    if type(count) is not int or count != 1:
        raise Reject('requires exactly one changed file')
    files = get_files(expected_repo, pr_number)
    if (not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], dict)
        or files[0].get('filename') != 'site/index.html'
        or files[0].get('status') not in ('added', 'modified')):
        raise Reject('disallowed changed file')
    blob = get_content(expected_repo, 'site/index.html', event_sha)
    if not isinstance(blob, dict) or blob.get('type') != 'file' or blob.get('encoding') != 'base64':
        raise Reject('bad content metadata')
    encoded = blob.get('content')
    if not isinstance(encoded, str):
        raise Reject('bad content')
    try:
        html_bytes = base64.b64decode(encoded.replace('\n', ''), validate=True)
        if len(html_bytes) > MAX_HTML:
            raise Reject('content exceeds size limit')
        html = html_bytes.decode('utf-8')
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise Reject('content decoding failed') from exc
    failures = audit(html)
    if not isinstance(failures, list) or failures:
        raise Reject('audit failed or invalid result')
    return {'result': 'PASS', 'repo': expected_repo, 'number': pr_number, 'sha': event_sha}
