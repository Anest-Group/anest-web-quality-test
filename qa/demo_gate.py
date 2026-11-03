#!/usr/bin/env python3
"""Demo-only read-only HTML smoke checks; NOT a production release approval."""
import sys
from html.parser import HTMLParser
from pathlib import Path

class Auditor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.main_count = 0
        self.has_lang = False
        self.has_title = False

    def handle_starttag(self, tag, attrs):
        keys = [key for key, _ in attrs]
        if len(keys) != len(set(keys)):
            self.errors.append(f"duplicate HTML attribute in <{tag}>")
        values = dict(attrs)
        if tag == "html":
            self.has_lang = bool(values.get("lang"))
        elif tag == "main":
            self.main_count += 1
        elif tag == "title":
            self.has_title = True
        elif tag == "img" and "alt" not in values:
            self.errors.append("image missing alt attribute")
        if tag == "a" and (values.get("href") or "").strip().lower().startswith("javascript:"):
            self.errors.append("javascript: link")

def audit_text(html):
    parser = Auditor()
    parser.feed(html)
    parser.close()
    if not parser.has_lang:
        parser.errors.append("html lang missing")
    if not parser.has_title:
        parser.errors.append("title missing")
    if parser.main_count != 1:
        parser.errors.append(f"main count is {parser.main_count}, expected 1")
    return parser.errors

if __name__ == "__main__":
    path = Path(sys.argv[1])
    errors = audit_text(path.read_text(encoding="utf-8"))
    for error in errors:
        print("FAIL:", error)
    if errors:
        raise SystemExit(1)
    print("PASS: demo only (NOT a production release approval)")
