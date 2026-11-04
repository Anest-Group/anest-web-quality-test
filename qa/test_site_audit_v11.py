import unittest
import contextlib
from io import StringIO
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from qa.site_audit_v11 import audit_text, main

GOOD = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="Example"><title>Valid page</title></head><body><main id="main"><h1>Heading</h1><a href="#main">Main</a><img src="a.webp" alt="Product photo"><form><label for="email">Email</label><input type="email" id="email"></form><button>Submit</button></main></body></html>'''

def codes(text, severity=None):
    return {f.code for f in audit_text(text) if severity is None or f.severity == severity}

class SiteAuditV11Tests(unittest.TestCase):
    def test_valid_has_no_findings(self): self.assertEqual(audit_text(GOOD), [])
    def test_missing_html_lang(self): self.assertIn('MISSING_LANG', codes(GOOD.replace('lang="ja"','')))
    def test_no_head(self): self.assertIn('HEAD_COUNT', codes(GOOD.replace('<head>', '<template>').replace('</head>', '</template>')))
    def test_no_title(self): self.assertIn('MISSING_TITLE', codes(GOOD.replace('Valid page','')))
    def test_no_main(self): self.assertIn('MAIN_COUNT', codes(GOOD.replace('<main id="main">','<section id="main">').replace('</main>','</section>')))
    def test_duplicate_attrs(self): self.assertIn('DUPLICATE_ATTRIBUTE',codes(GOOD.replace('id="main"','id="main" id="two"')))
    def test_duplicate_id(self): self.assertIn('DUPLICATE_ID',codes(GOOD.replace('id="email"','id="main"')))
    def test_missing_alt(self): self.assertIn('MISSING_IMG_ALT',codes(GOOD.replace('alt="Product photo"','')))
    def test_decorative_alt_allowed(self): self.assertNotIn('MISSING_IMG_ALT',codes(GOOD.replace('alt="Product photo"','alt=""')))
    def test_missing_src_warning(self): self.assertIn('MISSING_IMG_SRC',codes(GOOD.replace('src="a.webp"',''),'warning'))
    def test_missing_description_warning(self): self.assertIn('MISSING_DESCRIPTION',codes(GOOD.replace('<meta name="description" content="Example">',''),'warning'))
    def test_missing_viewport_warning(self): self.assertIn('MISSING_VIEWPORT',codes(GOOD.replace('<meta name="viewport" content="width=device-width, initial-scale=1">',''),'warning'))
    def test_missing_charset_warning(self): self.assertIn('MISSING_CHARSET',codes(GOOD.replace('<meta charset="utf-8">',''),'warning'))
    def test_bad_fragment_warning(self): self.assertIn('BROKEN_FRAGMENT',codes(GOOD.replace('href="#main"','href="#missing"'),'warning'))
    def test_good_fragment(self): self.assertNotIn('BROKEN_FRAGMENT',codes(GOOD))
    def test_unsafe_javascript(self): self.assertIn('UNSAFE_URL_SCHEME',codes(GOOD.replace('href="#main"','href="javascript:alert(1)"')))
    def test_unsafe_control_char_scheme(self): self.assertIn('UNSAFE_URL_SCHEME',codes(GOOD.replace('href="#main"','href="java&#10;script:alert(1)"')))
    def test_unsafe_data_scheme(self): self.assertIn('UNSAFE_URL_SCHEME',codes(GOOD.replace('href="#main"','href="data:text/html,hello"')))
    def test_blank_target_warning(self): self.assertIn('MISSING_NOOPENER',codes(GOOD.replace('href="#main"','href="https://example.org" target="_blank"'),'warning'))
    def test_blank_target_with_rel(self): self.assertNotIn('MISSING_NOOPENER',codes(GOOD.replace('href="#main"','href="https://example.org" target="_blank" rel="noopener"')))
    def test_unlabeled_control(self): self.assertIn('UNLABELED_CONTROL',codes(GOOD.replace('<label for="email">Email</label>','')))
    def test_wrapping_label(self): self.assertNotIn('UNLABELED_CONTROL',codes(GOOD.replace('<label for="email">Email</label><input type="email" id="email">','<label>Email <input type="email" id="email"></label>')))
    def test_aria_label_control(self): self.assertNotIn('UNLABELED_CONTROL',codes(GOOD.replace('<label for="email">Email</label>','').replace('id="email"','id="email" aria-label="Email"')))
    def test_aria_labelledby_control(self): self.assertNotIn('UNLABELED_CONTROL', codes(GOOD.replace('<label for="email">Email</label>','').replace('id="email"','id="email" aria-labelledby="main"')))
    def test_broken_aria_reference(self): self.assertIn('BROKEN_ARIA_REFERENCE',codes(GOOD.replace('id="email"','id="email" aria-describedby="missing"')))
    def test_valid_aria_reference(self): self.assertNotIn('BROKEN_ARIA_REFERENCE',codes(GOOD.replace('id="email"','id="email" aria-describedby="main"')))
    def test_submit_input_exempt(self): self.assertNotIn('UNLABELED_CONTROL',codes(GOOD.replace('<label for="email">Email</label><input type="email" id="email">','<input type="submit" value="Send">')))
    def test_unnamed_button(self): self.assertIn('UNNAMED_BUTTON',codes(GOOD.replace('<button>Submit</button>','<button></button>')))
    def test_button_aria_labelledby(self): self.assertNotIn('UNNAMED_BUTTON',codes(GOOD.replace('<button>Submit</button>','<button aria-labelledby="main"></button>')))
    def test_named_button_aria(self): self.assertNotIn('UNNAMED_BUTTON',codes(GOOD.replace('<button>Submit</button>','<button aria-label="Submit"></button>')))
    def test_empty_link_is_error(self): self.assertIn('UNNAMED_LINK',codes(GOOD.replace('>Main</a>','></a>'),'error'))
    def test_image_link_named(self): self.assertNotIn('UNNAMED_LINK',codes(GOOD.replace('<a href="#main">Main</a>','<a href="#main"><img src="img.png" alt="Go main"></a>')))
    def test_iframe_title(self): self.assertIn('UNNAMED_IFRAME',codes(GOOD.replace('</main>','<iframe src="https://example.org"></iframe></main>')))
    def test_inline_handler_warning(self): self.assertIn('INLINE_HANDLER',codes(GOOD.replace('<button>','<button onclick="alert(1)">'),'warning'))
    def test_http_resource_warning(self): self.assertIn('INSECURE_RESOURCE',codes(GOOD.replace('</head>','<script src="http://example.org/a.js"></script></head>'),'warning'))
    def test_password_autocomplete_warning(self): self.assertIn('PASSWORD_AUTOCOMPLETE',codes(GOOD.replace('</form>','<label for="pw">Password</label><input id="pw" type="password"></form>'),'warning'))


    def test_unsafe_form_action_javascript(self): self.assertIn('UNSAFE_FORM_ACTION',codes(GOOD.replace('<form>','<form action="javascript:alert(1)">')))
    def test_unsafe_form_action_data(self): self.assertIn('UNSAFE_FORM_ACTION',codes(GOOD.replace('<form>','<form action="data:text/html,evil">')))
    def test_form_action_http_warning(self): self.assertIn('INSECURE_FORM_ACTION',codes(GOOD.replace('<form>','<form action="http://example.org/send">'),'warning'))
    def test_safe_form_action(self): self.assertNotIn('UNSAFE_FORM_ACTION',codes(GOOD.replace('<form>','<form action="/send">')))
    def test_unsafe_formaction_button(self): self.assertIn('UNSAFE_FORM_ACTION',codes(GOOD.replace('<button>','<button formaction="javascript:alert(1)">')))
    def test_unsafe_formaction_image(self): self.assertIn('UNSAFE_FORM_ACTION',codes(GOOD.replace('</form>','<input type="image" alt="Send" formaction="data:text/html,x"></form>')))
    def test_unsafe_iframe_url(self): self.assertIn('UNSAFE_IFRAME_URL',codes(GOOD.replace('</main>','<iframe title="Test" src="javascript:alert(1)"></iframe></main>')))
    def test_safe_iframe_url(self): self.assertNotIn('UNSAFE_IFRAME_URL',codes(GOOD.replace('</main>','<iframe title="Test" src="/embed"></iframe></main>')))
    def test_unsafe_script_source(self): self.assertIn('UNSAFE_RESOURCE_URL',codes(GOOD.replace('</head>','<script src="data:text/javascript,alert(1)"></script></head>')))
    def test_unsafe_stylesheet_source(self): self.assertIn('UNSAFE_RESOURCE_URL',codes(GOOD.replace('</head>','<link href="javascript:evil()" rel="stylesheet"></head>')))
    def test_image_input_without_name(self): self.assertIn('UNLABELED_CONTROL',codes(GOOD.replace('</form>','<input type="image" src="submit.png"></form>')))
    def test_image_input_with_alt(self): self.assertNotIn('UNLABELED_CONTROL',codes(GOOD.replace('</form>','<input type="image" src="submit.png" alt="送信"></form>')))
    def test_plain_button_input_without_value(self): self.assertIn('UNLABELED_CONTROL',codes(GOOD.replace('</form>','<input type="button"></form>')))
    def test_plain_button_input_with_value(self): self.assertNotIn('UNLABELED_CONTROL',codes(GOOD.replace('</form>','<input type="button" value="送信"></form>')))
    def test_zoom_disabled_warning(self): self.assertIn('ZOOM_DISABLED',codes(GOOD.replace('width=device-width, initial-scale=1','width=device-width, user-scalable=no'),'warning'))
    def test_zoom_allowed(self): self.assertNotIn('ZOOM_DISABLED',codes(GOOD))


    def test_empty_label_for_rejected(self):
        broken = GOOD.replace('<label for="email">Email</label>','<label for="email"></label>')
        self.assertIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_whitespace_only_label_rejected(self):
        broken = GOOD.replace('<label for="email">Email</label>','<label for="email">   </label>')
        self.assertIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_empty_wrapping_label_rejected(self):
        broken = GOOD.replace('<label for="email">Email</label><input type="email" id="email">','<label><input type="email" id="email"></label>')
        self.assertIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_wrapping_label_text_allowed(self):
        broken = GOOD.replace('<label for="email">Email</label><input type="email" id="email">','<label><strong>Email</strong><input type="email" id="email"></label>')
        self.assertNotIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_empty_aria_labelledby_rejected(self):
        broken = GOOD.replace('<label for="email">Email</label>','').replace('id="email"','id="email" aria-labelledby="empty"').replace('<h1>Heading</h1>','<h1>Heading</h1><span id="empty"></span>')
        self.assertIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_aria_labelledby_heading_allowed(self):
        broken = GOOD.replace('<label for="email">Email</label>','').replace('id="email"','id="email" aria-labelledby="heading"').replace('<h1>Heading</h1>','<h1 id="heading">Heading</h1>')
        self.assertNotIn('UNLABELED_CONTROL', codes(broken, 'error'))

    def test_image_only_button_has_name(self):
        good = GOOD.replace('<button>Submit</button>', '<button><img src="send.png" alt="送信"></button>')
        self.assertNotIn('UNNAMED_BUTTON', codes(good, 'error'))

    def test_decorative_image_only_button_has_no_name(self):
        bad = GOOD.replace('<button>Submit</button>', '<button><img src="send.png" alt=""></button>')
        self.assertIn('UNNAMED_BUTTON', codes(bad, 'error'))

    def test_misnested_required_tags(self):
        bad = GOOD.replace('<button>Submit</button>', '<button><span>Submit</button></span>')
        self.assertIn('MISNESTED_HTML', codes(bad, 'error'))

    def test_unclosed_required_tag(self):
        bad = GOOD.replace('<button>Submit</button>', '<button>Submit')
        self.assertIn('UNCLOSED_HTML_TAG', codes(bad, 'error'))

    def test_explicit_self_closing_required_tag(self):
        bad = GOOD.replace('<button>Submit</button>', '<button/>')
        self.assertIn('SELF_CLOSING_NONVOID', codes(bad, 'error'))

    def test_void_tag_does_not_require_closing(self):
        self.assertNotIn('UNCLOSED_HTML_TAG', codes(GOOD, 'error'))

    def test_unnamed_link_is_error(self):
        bad = GOOD.replace('>Main</a>', '></a>')
        self.assertIn('UNNAMED_LINK', codes(bad, 'error'))

    def test_image_link_alt_provides_name(self):
        good = GOOD.replace('<a href="#main">Main</a>', '<a href="#main"><img src="nav.png" alt="Home"></a>')
        self.assertNotIn('UNNAMED_LINK', codes(good, 'error'))


    def _cli(self, html, *options):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.html'
            path.write_text(html, encoding='utf-8')
            stdout = StringIO()
            with patch.object(sys, 'argv', ['site_audit_v11.py', str(path), *options]), contextlib.redirect_stdout(stdout):
                result = main()
            return result, stdout.getvalue()

    def test_cli_valid_baseline_pass(self):
        status, output = self._cli(GOOD)
        self.assertEqual(status, 0)
        self.assertIn('PASS', output)

    def test_cli_required_error_fails(self):
        status, output = self._cli(GOOD.replace('<title>Valid page</title>', ''))
        self.assertEqual(status, 1)
        self.assertIn('FAIL', output)

    def test_cli_warning_default_is_visible_but_not_blocking(self):
        status, output = self._cli(GOOD.replace('<meta name="description" content="Example">', ''))
        self.assertEqual(status, 0)
        self.assertIn('MISSING_DESCRIPTION', output)

    def test_cli_warning_strict_fails(self):
        status, output = self._cli(GOOD.replace('<meta name="description" content="Example">', ''), '--fail-on-warning')
        self.assertEqual(status, 1)
        self.assertIn('FAIL', output)

    def test_cli_valid_strict_pass(self):
        status, output = self._cli(GOOD, '--fail-on-warning')
        self.assertEqual(status, 0)
        self.assertIn('PASS', output)

    def test_cli_json_failure(self):
        import json
        status, output = self._cli(GOOD.replace('<title>Valid page</title>', ''), '--json')
        data = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual(data["result"], "FAIL")
        self.assertTrue(any(x["code"] == "MISSING_TITLE" for x in data["findings"]))


    def test_optional_head_end_tag_not_false_rejected(self):
        good = GOOD.replace('</head>', '')
        self.assertFalse({'MISNESTED_HTML','UNCLOSED_HTML_TAG'} & codes(good, 'error'))

    def test_optional_document_end_tags_not_false_rejected(self):
        good = GOOD.replace('</head>', '').replace('</body>', '').replace('</html>', '')
        self.assertFalse({'MISNESTED_HTML','UNCLOSED_HTML_TAG'} & codes(good, 'error'))

    def test_misnested_explicit_section_tags_still_rejected(self):
        bad = GOOD.replace('<h1>Heading</h1>', '<section><h1>Heading</section></h1>')
        self.assertIn('MISNESTED_HTML', codes(bad, 'error'))

    def test_broken_label_target_rejected(self):
        bad = GOOD.replace('for="email"', 'for="absent"')
        self.assertIn('BROKEN_LABEL_REFERENCE', codes(bad, 'error'))

    def test_valid_label_target_allowed(self):
        self.assertNotIn('BROKEN_LABEL_REFERENCE', codes(GOOD, 'error'))

    def test_image_alt_used_for_aria_labelledby(self):
        good = GOOD.replace('<label for="email">Email</label>', '').replace(
            'id="email"', 'id="email" aria-labelledby="image-name"'
        ).replace('<h1>Heading</h1>', '<h1>Heading</h1><span id="image-name"><img src="name.png" alt="Email"></span>')
        self.assertNotIn('UNLABELED_CONTROL', codes(good, 'error'))

    def test_empty_image_alt_does_not_name_control(self):
        bad = GOOD.replace('<label for="email">Email</label>', '').replace(
            'id="email"', 'id="email" aria-labelledby="image-name"'
        ).replace('<h1>Heading</h1>', '<h1>Heading</h1><span id="image-name"><img src="name.png" alt=""></span>')
        self.assertIn('UNLABELED_CONTROL', codes(bad, 'error'))


    def test_direct_image_id_alt_names_control(self):
        good = GOOD.replace('<label for="email">Email</label>', '').replace(
            'id="email"', 'id="email" aria-labelledby="image-name"'
        ).replace('<h1>Heading</h1>', '<h1>Heading</h1><img id="image-name" src="name.png" alt="Email">')
        self.assertNotIn('UNLABELED_CONTROL', codes(good, 'error'))

    def test_direct_image_id_empty_alt_does_not_name_control(self):
        bad = GOOD.replace('<label for="email">Email</label>', '').replace(
            'id="email"', 'id="email" aria-labelledby="image-name"'
        ).replace('<h1>Heading</h1>', '<h1>Heading</h1><img id="image-name" src="name.png" alt="">')
        self.assertIn('UNLABELED_CONTROL', codes(bad, 'error'))

if __name__ == '__main__': unittest.main()
