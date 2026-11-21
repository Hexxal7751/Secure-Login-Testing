"""Language switch.

Pages are written in English. For another language the finished HTML is translated on the way out:
every piece of text that exactly matches an English phrase in translations_xx.py is replaced.
Text that has no translation (names, dynamic messages, the admin pages) simply stays English.

To add a language: create translations_xx.py with a dict {English text: translation}, then add it to
LANGUAGES and TABLES below.
"""
import html as _html
import re

from flask import request

from translations_es import ES
from translations_fr import FR

LANGUAGES = {"en": "English", "es": "Español", "fr": "Français"}
TABLES = {"es": ES, "fr": FR}

_SKIP = re.compile(r"(<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->)", re.S | re.I)
_TEXT = re.compile(r">([^<>]+)<")
_ATTR = re.compile(r'(\b(?:placeholder|aria-label|title|alt)=")([^"]*)(")')


def _norm(text):
    return re.sub(r"\s+", " ", _html.unescape(text)).strip()


def translate_html(markup, table):
    """Translate text nodes and a few attributes; script/style/comments are left alone."""
    def text(m):
        raw = m.group(1)
        found = table.get(_norm(raw))
        if not found:
            return m.group(0)
        lead = raw[:len(raw) - len(raw.lstrip())]
        tail = raw[len(raw.rstrip()):]
        return ">" + lead + _html.escape(found, quote=False) + tail + "<"

    def attr(m):
        found = table.get(_norm(m.group(2)))
        return m.group(1) + _html.escape(found, quote=True) + m.group(3) if found else m.group(0)

    parts = _SKIP.split(markup)
    for i in range(0, len(parts), 2):          # even parts are real markup, odd parts are skipped blocks
        parts[i] = _ATTR.sub(attr, _TEXT.sub(text, parts[i]))
    return "".join(parts)


def current_language():
    code = request.cookies.get("lang", "en")
    return code if code in LANGUAGES else "en"


def init_i18n(app):
    @app.context_processor
    def _inject():
        return {"lang": current_language(), "languages": LANGUAGES}

    @app.after_request
    def _translate(response):
        lang = current_language()
        if (lang == "en" or response.mimetype != "text/html" or response.direct_passthrough
                or response.status_code == 304):
            return response
        markup = response.get_data(as_text=True)
        markup = markup.replace('<html lang="en">', f'<html lang="{lang}">', 1)
        response.set_data(translate_html(markup, TABLES[lang]))
        return response


# END OF i18n.py
