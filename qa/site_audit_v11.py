"""V11: offline single-HTML preflight (not a browser test or release certification).

No code execution from HTML, network requests, dependencies, or write operations.
This file is a candidate for review, not a trusted branch-protection policy yet.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

MAX_INPUT_BYTES = 512_000
UNSAFE_SCHEMES = {"javascript", "vbscript", "data", "file"}
INTERACTIVE_TAGS = {"input", "select", "textarea"}
UNLABELED_INPUT_TYPES = {"hidden", "reset", "submit"}
# These elements require an explicit end tag in HTML; not a full HTML5 validator.
REQUIRED_END_TAGS = {
    "main", "div", "section", "article", "nav", "aside", "header", "footer",
    "form", "label", "button", "a", "span", "strong", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "table",
    "fieldset", "legend", "select", "textarea",
}
VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    line: int


class SiteAudit(HTMLParser):
    """Conservative checks; no claims of visual, WCAG or vulnerability coverage."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings: list[Finding] = []
        self.ids: set[str] = set()
        self.id_references: list[tuple[str, str, int]] = []
        self.fragments: list[tuple[str, int]] = []
        self.labels: list[dict] = []
        self.label_stack: list[dict] = []
        self.inputs: list[dict] = []
        self.element_names: dict[str, list[str]] = {}
        self.named_element_stack: list[tuple[str, str]] = []
        self.open_tags: list[tuple[str, int]] = []
        self.title_depth = 0
        self.title_text: list[str] = []
        self.head_count = 0
        self.main_count = 0
        self.h1_count = 0
        self.has_lang = False
        self.has_title = False
        self.has_viewport = False
        self.has_description = False
        self.has_charset = False
        self.buttons: list[dict] = []
        self.button_stack: list[dict] = []
        self.links: list[dict] = []
        self.link_stack: list[dict] = []

    def add(self, severity: str, code: str, message: str, line: int | None = None):
        self.findings.append(Finding(severity, code, message, line or self.getpos()[0]))

    @staticmethod
    def _scheme(value: str) -> str:
        # Control characters can be ignored by browsers when interpreting schemes.
        normalized = re.sub(r"[\x00-\x20\x7f]", "", value).lower()
        return normalized.split(":", 1)[0] if ":" in normalized else ""

    def handle_startendtag(self, tag, attrs):
        if tag in REQUIRED_END_TAGS:
            self.add("error", "SELF_CLOSING_NONVOID", f"Self-closing <{tag}/> is not valid HTML syntax")
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_starttag(self, tag, attrs):
        line = self.getpos()[0]
        names = [k.lower() for k, _ in attrs]
        if len(set(names)) != len(names):
            self.add("error", "DUPLICATE_ATTRIBUTE", f"<{tag}> contains duplicate attributes", line)
        data = dict(attrs)
        element_id = (data.get("id") or "").strip()
        if element_id:
            if element_id in self.ids:
                self.add("error", "DUPLICATE_ID", f"Duplicate id: {element_id}", line)
            self.ids.add(element_id)
            self.element_names[element_id] = []
            if tag not in VOID_TAGS:
                self.named_element_stack.append((tag, element_id))
        if tag in REQUIRED_END_TAGS:
            self.open_tags.append((tag, line))
        for key in ("aria-labelledby", "aria-describedby"):
            for target in (data.get(key) or "").split():
                self.id_references.append((target, key, line))
        if tag == "label":
            current_label = {"for": (data.get("for") or "").strip(), "text": [], "line": line}
            self.labels.append(current_label)
            self.label_stack.append(current_label)
        if tag == "html":
            self.has_lang = bool((data.get("lang") or "").strip())
        elif tag == "head":
            self.head_count += 1
        elif tag == "title":
            self.has_title = True
            self.title_depth += 1
        elif tag == "meta":
            if "charset" in data:
                self.has_charset = True
            key = (data.get("name") or "").strip().lower()
            if key == "viewport" and (data.get("content") or "").strip():
                self.has_viewport = True
                viewport = (data["content"] or "").lower()
                if re.search(r"user-scalable\s*=\s*[\x27\x22]?(?:no|0)\b", viewport):
                    self.add("warning", "ZOOM_DISABLED", "Do not disable user zoom on mobile", line)
            if key == "description" and (data.get("content") or "").strip():
                self.has_description = True
        elif tag == "main":
            self.main_count += 1
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "form":
            action = (data.get("action") or "").strip()
            if self._scheme(action) in UNSAFE_SCHEMES:
                self.add("error", "UNSAFE_FORM_ACTION", "Form action uses an unsafe URL scheme", line)
            elif action.lower().startswith("http://"):
                self.add("warning", "INSECURE_FORM_ACTION", "Form action uses plain HTTP", line)
        elif tag == "img":
            if "alt" not in data:
                self.add("error", "MISSING_IMG_ALT", "Image has no alt attribute", line)
            if not (data.get("src") or data.get("srcset")):
                self.add("warning", "MISSING_IMG_SRC", "Image has no src or srcset", line)
        elif tag == "iframe":
            if not (data.get("title") or "").strip():
                self.add("error", "UNNAMED_IFRAME", "Iframe needs a descriptive title", line)
        elif tag in INTERACTIVE_TAGS:
            type_ = (data.get("type") or "text").strip().lower()
            if tag != "input" or type_ not in UNLABELED_INPUT_TYPES:
                accessible_name = (data.get("aria-label") or "").strip()
                if tag == "input" and type_ == "button":
                    accessible_name = accessible_name or (data.get("value") or "").strip()
                if tag == "input" and type_ == "image":
                    accessible_name = accessible_name or (data.get("alt") or "").strip()
                self.inputs.append({
                    "tag": tag, "type": type_, "id": element_id,
                    "aria_label": accessible_name,
                    "aria_labelledby": (data.get("aria-labelledby") or "").strip(),
                    "wrapping_labels": tuple(self.label_stack),
                    "line": line,
                })
            if tag == "input" and type_ == "password" and data.get("autocomplete") is None:
                self.add("warning", "PASSWORD_AUTOCOMPLETE", "Password control should declare an appropriate autocomplete value", line)
        elif tag == "button":
            button = {"line": line, "label": (data.get("aria-label") or "").strip(), "labelledby": (data.get("aria-labelledby") or "").strip(), "text": []}
            self.buttons.append(button)
            self.button_stack.append(button)
        elif tag == "a":
            href = data.get("href")
            if href is None:
                self.add("warning", "MISSING_HREF", "Anchor has no href", line)
            else:
                scheme = self._scheme(href)
                if scheme in UNSAFE_SCHEMES:
                    self.add("error", "UNSAFE_URL_SCHEME", "Unsafe URL scheme in link", line)
                if href.startswith("#") and len(href) > 1:
                    self.fragments.append((unquote(href[1:]), line))
                if (data.get("target") or "").lower() == "_blank":
                    rel = set((data.get("rel") or "").lower().split())
                    if "noopener" not in rel and "noreferrer" not in rel:
                        self.add("warning", "MISSING_NOOPENER", "target=_blank should include rel=noopener or noreferrer", line)
            anchor = {"line": line, "label": (data.get("aria-label") or "").strip(), "labelledby": (data.get("aria-labelledby") or "").strip(), "text": [], "img_alt": []}
            self.links.append(anchor)
            self.link_stack.append(anchor)
        elif tag in ("script", "link"):
            url = data.get("src") if tag == "script" else data.get("href")
            if url and self._scheme(url) in UNSAFE_SCHEMES:
                self.add("error", "UNSAFE_RESOURCE_URL", f"Unsafe {tag} resource URL", line)
            elif url and url.lower().startswith("http://"):
                self.add("warning", "INSECURE_RESOURCE", f"Review insecure {tag} resource reference", line)
        if tag in ("button", "input") and self._scheme(data.get("formaction") or "") in UNSAFE_SCHEMES:
            self.add("error", "UNSAFE_FORM_ACTION", "Submit control has unsafe formaction URL", line)
        if tag == "iframe" and self._scheme(data.get("src") or "") in UNSAFE_SCHEMES:
            self.add("error", "UNSAFE_IFRAME_URL", "Iframe uses an unsafe source URL", line)
        for key in names:
            if key.startswith("on") and len(key) > 2:
                self.add("warning", "INLINE_HANDLER", "Inline event handler requires security review", line)
        if tag == "img":
            alt = (data.get("alt") or "").strip()
            if self.link_stack:
                self.link_stack[-1]["img_alt"].append(alt)
            if self.button_stack:
                self.button_stack[-1]["text"].append(alt)
            for label in self.label_stack:
                label["text"].append(alt)

    def handle_endtag(self, tag):
        if tag in REQUIRED_END_TAGS:
            if not self.open_tags or self.open_tags[-1][0] != tag:
                self.add("error", "MISNESTED_HTML", f"Unexpected or incorrectly nested </{tag}>")
                # Recover only through an existing matching open tag.
                matching = next((i for i in range(len(self.open_tags) - 1, -1, -1)
                                 if self.open_tags[i][0] == tag), None)
                if matching is not None:
                    del self.open_tags[matching:]
            else:
                self.open_tags.pop()
        if self.named_element_stack:
            matching = next((i for i in range(len(self.named_element_stack) - 1, -1, -1)
                             if self.named_element_stack[i][0] == tag), None)
            if matching is not None:
                del self.named_element_stack[matching:]
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag == "label" and self.label_stack:
            self.label_stack.pop()
        if tag == "button" and self.button_stack:
            self.button_stack.pop()
        if tag == "a" and self.link_stack:
            self.link_stack.pop()

    def handle_data(self, data):
        if self.title_depth:
            self.title_text.append(data)
        if self.button_stack:
            self.button_stack[-1]["text"].append(data)
        if self.link_stack:
            self.link_stack[-1]["text"].append(data)
        for label in self.label_stack:
            label["text"].append(data)
        for _, element_id in self.named_element_stack:
            self.element_names[element_id].append(data)

    def finish(self) -> list[Finding]:
        if not self.has_lang:
            self.add("error", "MISSING_LANG", "html element must declare lang", 1)
        if self.head_count != 1:
            self.add("error", "HEAD_COUNT", "Expected exactly one head", 1)
        if not self.has_title or not "".join(self.title_text).strip():
            self.add("error", "MISSING_TITLE", "Provide a non-empty title", 1)
        if self.main_count != 1:
            self.add("error", "MAIN_COUNT", "Expected exactly one main landmark", 1)
        if self.h1_count != 1:
            self.add("warning", "H1_COUNT", "Recommend one primary h1", 1)
        if not self.has_viewport:
            self.add("warning", "MISSING_VIEWPORT", "Viewport meta is recommended for mobile layout", 1)
        if not self.has_description:
            self.add("warning", "MISSING_DESCRIPTION", "Meta description is recommended for search snippets", 1)
        if not self.has_charset:
            self.add("warning", "MISSING_CHARSET", "Explicit charset declaration is recommended", 1)
        for id_, key, line in self.id_references:
            if id_ not in self.ids:
                self.add("error", "BROKEN_ARIA_REFERENCE", f"{key} references missing id: {id_}", line)
        for id_, line in self.fragments:
            if id_ not in self.ids:
                self.add("warning", "BROKEN_FRAGMENT", f"In-page link refers to missing id: {id_}", line)
        if self.open_tags:
            for tag, start_line in self.open_tags:
                self.add("error", "UNCLOSED_HTML_TAG", f"Unclosed <{tag}>", start_line)
        def has_labelledby(value: str) -> bool:
            if not value:
                return False
            targets = value.split()
            return all(target in self.ids for target in targets) and bool(
                "".join("".join(self.element_names.get(target, [])) for target in targets).strip()
            )
        label_text_by_id: dict[str, list[str]] = {}
        for label in self.labels:
            if label["for"]:
                label_text_by_id.setdefault(label["for"], []).append("".join(label["text"]).strip())
        for control in self.inputs:
            label_text = any("".join(item["text"]).strip() for item in control["wrapping_labels"])
            matching = any(label.strip() for label in label_text_by_id.get(control["id"], [])) if control["id"] else False
            if label_text or matching or control["aria_label"] or has_labelledby(control["aria_labelledby"]):
                continue
            self.add("error", "UNLABELED_CONTROL", f'<{control["tag"]}> ({control["type"]}) needs a non-empty accessible label', control["line"])
        for button in self.buttons:
            if not button["label"] and not has_labelledby(button["labelledby"]) and not "".join(button["text"]).strip():
                self.add("error", "UNNAMED_BUTTON", "Button needs an accessible name", button["line"])
        for link in self.links:
            if not link["label"] and not has_labelledby(link["labelledby"]) and not "".join(link["text"]).strip() and not any(link["img_alt"]):
                self.add("error", "UNNAMED_LINK", "Link needs a discernible name", link["line"])
        return sorted(self.findings, key=lambda v: (v.line, v.code))


def audit_text(source: str) -> list[Finding]:
    parser = SiteAudit()
    try:
        parser.feed(source)
        parser.close()
    except (ValueError, AssertionError) as exc:
        return [Finding("error", "PARSER_ERROR", f"Invalid HTML input: {type(exc).__name__}", 1)]
    return parser.finish()


def main() -> int:
    ap = argparse.ArgumentParser(description="Static HTML preflight (NOT production quality certification)")
    ap.add_argument("html", type=Path)
    ap.add_argument("--json", action="store_true", help="Machine-readable findings")
    ap.add_argument("--fail-on-warning", action="store_true")
    args = ap.parse_args()
    try:
        if args.html.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("HTML is larger than permitted 512KB")
        text = args.html.read_text(encoding="utf-8")
        findings = audit_text(text)
    except (OSError, UnicodeError, ValueError) as exc:
        findings = [Finding("error", "READ_ERROR", f"Could not read HTML: {exc}", 1)]
    failed = any(v.severity == "error" or args.fail_on_warning for v in findings)
    if args.json:
        print(json.dumps({"result": "FAIL" if failed else "PASS", "scope": "static-html-only", "findings": [asdict(v) for v in findings]}, ensure_ascii=False, indent=2))
    else:
        for v in findings:
            print(f"{v.severity.upper()} [{v.code}] line {v.line}: {v.message}")
        print("FAIL" if failed else "PASS", "(offline preflight only; not a visual/browser/security certification)")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
