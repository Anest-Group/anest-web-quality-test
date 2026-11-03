#!/usr/bin/env python3
"""Trusted baseline static audit for an isolated demonstration repository.

NOT comprehensive web QA. Does not run any code from the candidate tree.
Import this module only from a verified PR base commit; never from the PR head.
"""
from __future__ import annotations
import argparse
from html.parser import HTMLParser
from pathlib import Path

PROTECTED_PATHS = ('.github/', 'qa/', '.claude/', 'CODEOWNERS', '.gitignore')

class Inspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.errors = []
        self.main_count = 0
        self.h1_count = 0
        self.lang = False
        self.title_started = False
        self.title_text = ''
        self.head_count = 0
    def handle_starttag(self, tag, attrs):
        keys = [name.lower() for name, _ in attrs]
        if len(keys) != len(set(keys)):
            self.errors.append('duplicate attribute in <'+tag+'>')
        d = dict(attrs)
        if tag == 'html': self.lang = bool((d.get('lang') or '').strip())
        if tag == 'main': self.main_count += 1
        if tag == 'h1': self.h1_count += 1
        if tag == 'head': self.head_count += 1
        if tag == 'title': self.title_started = True
        if tag == 'img' and 'alt' not in d: self.errors.append('missing image alt')
        if tag == 'a' and (d.get('href') or '').strip().lower().startswith(('javascript:', 'data:')):
            self.errors.append('unsafe link scheme')
    def handle_endtag(self, tag):
        if tag == 'title': self.title_started = False
    def handle_data(self, data):
        if self.title_started: self.title_text += data

def audit_html(source: str) -> list[str]:
    parser = Inspector()
    parser.feed(source)
    parser.close()
    if not parser.lang: parser.errors.append('html lang is missing')
    if not parser.head_count: parser.errors.append('head is missing')
    if not parser.title_text.strip(): parser.errors.append('non-empty title is missing')
    if parser.main_count != 1: parser.errors.append('expected exactly one main')
    if parser.h1_count != 1: parser.errors.append('expected exactly one h1')
    return parser.errors

def audit_changed_files(paths: list[str]) -> list[str]:
    errors = []
    if not paths: return ['no changed files supplied to policy check']
    for name in paths:
        normalized = name.replace('\\', '/')
        if normalized.startswith('/') or '..' in normalized.split('/'):
            errors.append('unsafe changed path: ' + name)
        elif any(normalized == p or normalized.startswith(p) for p in PROTECTED_PATHS):
            errors.append('protected check infrastructure changed: ' + name)
    return errors

def inspect(candidate_path: Path, changed: list[str]) -> list[str]:
    try:
        data = candidate_path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return ['candidate HTML not readable']
    return audit_html(data) + audit_changed_files(changed)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--candidate',type=Path,required=True)
    ap.add_argument('--changed-file',action='append',default=[])
    args = ap.parse_args()
    bad = inspect(args.candidate,args.changed_file)
    for error in bad: print('FAIL:',error)
    if bad: return 1
    print('PASS: protected baseline demo preflight (NOT full quality approval)')
    return 0

if __name__=='__main__': raise SystemExit(main())
