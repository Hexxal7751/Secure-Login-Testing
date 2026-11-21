"""Guards against the problems that broke deployments before: files cut off while copying,
missing routes referenced by templates, and typos that only fail at run time."""
import ast
import builtins
import glob
import importlib
import os
import re
import symtable

import jinja2

from helpers import A, MODULES, ROOT, setup

PY_FILES = ("app", "core", "routes_auth", "routes_account", "routes_admin", "routes_misc",
            "i18n", "translations_es", "translations_fr")
MAX_CHARS = 90_000      # files above ~100,000 characters get cut off when copied on a phone


def test_every_python_file_is_complete_and_small():
    for name in PY_FILES:
        text = open(os.path.join(ROOT, name + ".py"), encoding="utf-8").read()
        ast.parse(text)
        assert text.rstrip().splitlines()[-1].strip() == f"# END OF {name}.py", name
        assert len(text) < MAX_CHARS, f"{name}.py is {len(text)} characters"


def test_all_templates_parse_and_every_url_for_endpoint_exists():
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(ROOT, "templates")))
    endpoints = set()
    for path in glob.glob(os.path.join(ROOT, "templates", "*.html")):
        env.get_template(os.path.basename(path))
        endpoints.update(re.findall(r"url_for\('([a-z_]+)'", open(path, encoding="utf-8").read()))
    endpoints.discard("static")
    missing = sorted(e for e in endpoints if e not in A.app.view_functions)
    assert not missing, missing


def test_no_undefined_names_inside_functions():
    problems = []
    for mod in MODULES:
        src = open(mod.__file__, encoding="utf-8").read()

        def walk(table):
            if table.get_type() == "function":
                for sym in table.get_symbols():
                    name = sym.get_name()
                    if sym.is_global() and sym.is_referenced() and not hasattr(mod, name) \
                            and not hasattr(builtins, name):
                        problems.append(f"{mod.__name__}: {name} (in {table.get_name()})")
            for child in table.get_children():
                walk(child)
        walk(symtable.symtable(src, mod.__file__, "exec"))
    assert not problems, problems


def test_translations_have_no_empty_values():
    for name in ("translations_es", "translations_fr"):
        table = getattr(importlib.import_module(name), name[-2:].upper())
        assert len(table) > 250 and all(k.strip() and v.strip() for k, v in table.items())


def test_every_page_renders_for_a_signed_out_visitor():
    setup()
    from helpers import Client
    c = Client()
    for path in ("/", "/register", "/forgot-password", "/status", "/status.json"):
        assert c.get(path).status_code == 200, path
