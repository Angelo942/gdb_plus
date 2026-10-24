"""
Every public name of the Debugger class and of the package is used by at least one test, or says why not.
One row per name in the dashboard: working (a test uses it), not covered (the justification below), failing
(neither, or a justification that is not needed any more). Which domains a feature works on is the job of the
integration matrix: this only guarantees that nothing public is left out of it.
"""
import ast
import inspect
import re
from pathlib import Path

import pytest

import gdb_plus
from gdb_plus import Debugger

TESTS = Path(__file__).resolve().parent.parent

# name -> why no test uses it
JUSTIFIED = {
    "reset": "an empty stub (its body is `...`): restarting the process is not implemented",
}

# Package exports with a justification (the rest must appear in a test)
JUSTIFIED_EXPORTS = {
    "Inner_Debugger": "legacy amd64-only helper to debug through the tracer, not developed any more (CLAUDE.md): only imported",
}


def _without_docstrings(source):
    """The docstrings describe the tests for the dashboard: a method they mention is not a method a test uses"""
    lines = source.splitlines()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                lines[first.lineno - 1:first.end_lineno] = [""] * (first.end_lineno - first.lineno + 1)
    return "\n".join(lines)


def _sources():
    sources = []
    for path in sorted(TESTS.glob("*/test_*.py")):
        if path.resolve() != Path(__file__).resolve():
            sources.append(_without_docstrings(path.read_text()))
    sources += [path.read_text() for path in sorted(TESTS.glob("*/conftest.py"))]
    return "\n".join(sources)


SOURCES = _sources()


def _public_names():
    return sorted(name for name in dir(Debugger) if not name.startswith("_"))


def _used(name):
    return re.search(r"\." + re.escape(name) + r"\b", SOURCES) is not None


def _alias_of(name):
    """The other public names bound to the same function or property (until = continue_until...)"""
    # Looked up through the MRO: an alias lives in the mixin of its feature area, not in Debugger.__dict__
    value = inspect.getattr_static(Debugger, name, None)
    return [other for other in _public_names() if other != name and inspect.getattr_static(Debugger, other, None) is value and value is not None]


@pytest.mark.parametrize("name", _public_names())
def test_public_method_is_tested(name):
    """
    This public name of Debugger is used by at least one test (directly or through an alias), or JUSTIFIED says why not.
    A name that gets a test must lose its justification.
    """
    used = _used(name)
    if name in JUSTIFIED:
        assert not used, f"a test uses {name} now: remove its justification"
        pytest.skip(f"not covered: {JUSTIFIED[name]}")
    if used:
        return
    aliases = [other for other in _alias_of(name) if _used(other)]
    assert aliases, f"no test uses Debugger.{name}: write one, or add a justification to JUSTIFIED"


@pytest.mark.parametrize("name", sorted(set(gdb_plus.__all__) if hasattr(gdb_plus, "__all__") else
                                        ["Debugger", "Structure", "Array", "String", "Inner_Debugger", "SKIP_SYSCALL", "SHOULD_STOP"]))
def test_export_is_tested(name):
    """This name exported by the gdb_plus package is used by at least one test, or JUSTIFIED_EXPORTS says why not."""
    used = re.search(r"\b" + re.escape(name) + r"\b", SOURCES) is not None
    if name in JUSTIFIED_EXPORTS:
        pytest.skip(f"not covered: {JUSTIFIED_EXPORTS[name]}")
    assert used, f"no test uses gdb_plus.{name}"


CONSTRUCTOR = [name for name in inspect.signature(Debugger.__init__).parameters if name not in ["self", "target"]]


@pytest.mark.parametrize("name", CONSTRUCTOR)
def test_constructor_parameter_is_tested(name):
    """Some test passes this keyword argument to Debugger(...)."""
    assert re.search(r"\b" + re.escape(name) + r"=", SOURCES), f"no test passes Debugger(..., {name}=...)"


def test_justifications_name_real_methods():
    """
    Every entry of JUSTIFIED is still a public name of Debugger (no stale justification left behind after a rename).
    """
    assert set(JUSTIFIED) <= set(_public_names())
