"""
support/affected.py picks the tests that reach a change (pytest --affected, the pre-commit hook): which definitions
changed, which tests the index says execute them, and how the index is built from coverage contexts.
"""
import textwrap

from coverage import CoverageData

from support.affected import Definitions, _exception_type, build_index, select


def _src(text):
    return textwrap.dedent(text).lstrip()


OLD = _src('''
    TABLE = {"amd64": 1}

    class Debugger:
        def step(self):
            """Step"""
            return 1  # one instruction

        def cont(self):
            return 2

    def helper():
        return TABLE["amd64"]
''')

INDEX = {
    "tests": ["integration/test_control_flow.py::test_step[gdb]", "integration/test_control_flow.py::test_step[arm]",
              "integration/test_breakpoints.py::test_b[gdb]", "unit/test_arch_tables.py::test_table"],
    "functions": {"gdb_plus/gdb_plus.py::Debugger.step": [0, 1], "gdb_plus/gdb_plus.py::Debugger.cont": [2],
                  "gdb_plus/gdb_plus.py::helper": [3]},
}


def _select(path, old, new, index=INDEX, package=None):
    return select(index=index, files=[(path, old, new)], package=package)


def test_comment_and_docstring_edits_select_nothing():
    """Changing a comment and a docstring, and moving a method below another, changes no AST: nothing runs."""
    new = OLD.replace("# one instruction", "# a single instruction").replace('"""Step"""', '"""Step once"""')
    step = new[new.index("    def step"):new.index("    def cont")]
    new = new.replace(step, "").replace("    def cont(self):\n        return 2\n", "    def cont(self):\n        return 2\n\n" + step)
    selection = _select("gdb_plus/gdb_plus.py", OLD, new)
    assert not selection
    assert not selection.code_changed


def test_a_changed_method_selects_the_tests_that_execute_it():
    """Editing the body of Debugger.step selects the two parametrized runs the index lists for it, and the unit tier."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD.replace("return 1", "return 3"))
    assert set(selection.prefixes) == {"integration/test_control_flow.py::test_step[gdb]",
                                       "integration/test_control_flow.py::test_step[arm]", "unit/"}
    assert not selection.selects("integration/test_breakpoints.py::test_b[gdb]", set(INDEX["tests"]))


def test_a_changed_assignment_selects_the_functions_that_use_the_name():
    """A new value in the module level TABLE selects the tests of helper(), the only function reading TABLE."""
    new = OLD.replace('{"amd64": 1}', '{"amd64": 2}')
    selection = _select("gdb_plus/gdb_plus.py", OLD, new, package={"gdb_plus/gdb_plus.py": Definitions(new)})
    assert set(selection.prefixes) == {"unit/test_arch_tables.py::test_table", "unit/"}


def test_a_changed_class_header_selects_all_its_methods():
    """Adding a base class to Debugger selects the tests of every method of the class."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD.replace("class Debugger:", "class Debugger(object):"))
    assert set(selection.prefixes) == {*INDEX["tests"][:3], "unit/"}


def test_a_star_import_selects_everything():
    """A new `from x import *` can shadow any name: the whole suite runs."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, "from pwn import *\n" + OLD)
    assert selection.everything
    assert selection.selects("regression/test_cube.py::test_anything")


def test_a_function_no_test_executes_is_reported():
    """A new function has no entry in the index: it is reported as unreached instead of selecting anything for it."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD + "\ndef brand_new():\n    return 4\n")
    assert selection.unreached == ["gdb_plus/gdb_plus.py::brand_new"]
    assert set(selection.prefixes) == {"unit/"}


def test_a_changed_test_runs_with_all_its_parameters():
    """Editing test_a selects every parametrization of test_a, and not test_ab whose name starts the same way."""
    old = "def test_a(backend):\n    assert 1\n\ndef test_ab():\n    assert 1\n"
    selection = _select("tests/integration/test_x.py", old, old.replace("assert 1", "assert 2", 1))
    assert selection.selects("integration/test_x.py::test_a[gdb]")
    assert selection.selects("integration/test_x.py::test_a")
    assert not selection.selects("integration/test_x.py::test_ab")


def test_a_changed_helper_selects_the_tests_that_use_it_through_other_helpers():
    """_inner is used by the _gap decorator, which marks test_c: changing _inner selects test_c and not test_d."""
    old = _src('''
        def _inner():
            return 1

        def _gap(test):
            _inner()
            return test

        @_gap
        def test_c():
            pass

        def test_d(basic):
            pass
    ''')
    selection = _select("tests/integration/test_x.py", old, old.replace("return 1", "return 2"))
    assert set(selection.prefixes) == {"integration/test_x.py::test_c", "unit/"}


def test_pytestmark_selects_the_whole_module():
    """pytestmark applies to every test of the module, which no test names: the whole module runs."""
    old = "import pytest\npytestmark = []\n\ndef test_a():\n    pass\n"
    selection = _select("tests/integration/test_x.py", old, old.replace("[]", "[pytest.mark.qemu('arm')]"))
    assert selection.selects("integration/test_x.py::test_a[gdb]")
    assert selection.selects("integration/test_x.py::test_zzz")


def test_support_files_select_everything_and_documentation_nothing():
    """A change in tests/support can affect any test; a change in the docs or a Markdown file affects none."""
    assert _select("tests/support/targets.py", "A = 1\n", "A = 2\n").everything
    assert not _select("docs/index.html", None, None)
    assert not _select("tests/README.md", None, None)


def test_tests_the_index_has_never_seen_run_when_code_changed():
    """A test added after the index was built runs, because nothing says it doesn't reach the change."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD.replace("return 1", "return 3"))
    known = set(INDEX["tests"])
    assert selection.selects("integration/test_new.py::test_added_later[gdb]", known)
    assert not selection.selects("integration/test_breakpoints.py::test_b[gdb]", known)


def test_without_an_index_a_code_change_runs_everything():
    """With no index there is no way to tell which tests reach the change: the whole suite runs, and says why."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD.replace("return 1", "return 3"), index=None)
    assert any("no index" in reason for reason in selection.everything)


def test_the_index_ignores_the_def_line_executed_at_import(tmp_path):
    """
    The def line of a function runs when its module is imported, under whatever test imports it: the index only
    credits the tests that executed a line of the body.
    """
    source = tmp_path / "gdb_plus" / "gdb_plus.py"
    source.parent.mkdir()
    source.write_text(OLD)
    lines = OLD.splitlines()
    def_line = lines.index("    def cont(self):") + 1
    data = CoverageData(no_disk=True)
    data.set_context("unit/test_import.py::test_imports_everything")
    data.add_lines({str(source): [def_line]})
    data.set_context("integration/test_control_flow.py::test_cont[gdb]")
    data.add_lines({str(source): [def_line + 1]})
    index = build_index(data, tmp_path, collected=[])
    tests = index["tests"]
    assert [tests[i] for i in index["functions"]["gdb_plus/gdb_plus.py::Debugger.cont"]] == \
        ["integration/test_control_flow.py::test_cont[gdb]"]


def test_recorded_failures_are_compared_on_the_exception_type():
    """
    The hook excuses a failure already recorded only if it is the same kind: the type before the first colon, since
    the rest of the message holds addresses and pids that change between runs.
    """
    assert _exception_type("TypeError: unsupported operand type(s) for ^: 'NoneType' and 'int'") == "TypeError"
    assert _exception_type("AssertionError: assert 3 == 1\n+  where 3 = len([1, 2, 3])") == "AssertionError"
    assert _exception_type("EOFError") == "EOFError"
    assert _exception_type("") == ""


########################## LINE LEVEL ##########################

DISPATCH = _src('''
    class Debugger:
        def step(self, n):
            self.count = n
            if self.gdb is not None:
                self.gdb.step(n)
                return "gdb"
            elif self.libdebug is not None:
                self.libdebug.step(n)
                return "libdebug"
            while True:
                break
            return None
''')

GDB, LIBDEBUG = "integration/test_control_flow.py::test_step[gdb]", "integration/test_control_flow.py::test_step[libdebug]"


def _line(source, text):
    return next(i for i, line in enumerate(source.splitlines(), 1) if text in line)


def _line_index(tmp_path, source, runs):
    """An index built from coverage data where each test executed the lines holding the given texts (if present)"""
    path = tmp_path / "gdb_plus" / "gdb_plus.py"
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    data = CoverageData(no_disk=True)
    for nodeid, texts in runs.items():
        data.set_context(nodeid)
        data.add_lines({str(path): [_line(source, text) for text in texts if text in source]})
    return build_index(data, tmp_path, collected=[])


def _dispatch_index(tmp_path, source=DISPATCH):
    common = ["self.count = n", "if self.gdb"]
    return _line_index(tmp_path, source, {GDB: common + ["self.gdb.step", 'return "gdb"'],
                                          LIBDEBUG: common + ["elif self.libdebug", "self.libdebug.step",
                                                              'return "libdebug"']})


def _selected(selection):
    return set(selection.prefixes) - {"unit/"}


def test_a_change_in_a_branch_selects_the_tests_that_took_it(tmp_path):
    """Editing the libdebug branch of step selects the libdebug run, not the gdb run that executes the same function."""
    new = DISPATCH.replace("self.libdebug.step(n)", "self.libdebug.step(n, quiet=True)")
    selection = _select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))
    assert _selected(selection) == {LIBDEBUG}
    assert selection.prefixes[LIBDEBUG] == {f"executes gdb_plus/gdb_plus.py:{_line(new, 'quiet=True')} (Debugger.step)"}


def test_an_added_statement_selects_the_tests_that_ran_the_one_before(tmp_path):
    """A line added after self.gdb.step(n) runs only where that call ran: the gdb run."""
    new = DISPATCH.replace("self.gdb.step(n)\n", "self.gdb.step(n)\n            self.gdb.flush()\n")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))) == {GDB}


def test_a_statement_added_first_in_a_block_selects_the_tests_that_entered_it(tmp_path):
    """
    A line added at the top of the gdb branch, or replacing the first line of the function, runs whenever the old first
    statement of that block ran.
    """
    index = _dispatch_index(tmp_path)
    new = DISPATCH.replace("    self.gdb.step(n)\n", "    log('gdb')\n            self.gdb.step(n)\n")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == {GDB}
    new = DISPATCH.replace("self.count = n", "self.total = n")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == {GDB, LIBDEBUG}


def test_a_new_elif_selects_the_tests_that_reached_the_else(tmp_path):
    """An elif inserted after the gdb branch is evaluated only when gdb is None: the libdebug run."""
    new = DISPATCH.replace("        elif self.libdebug", "        elif self.qemu is not None:\n"
                                                         "            return 'qemu'\n        elif self.libdebug")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))) == {LIBDEBUG}


def test_a_changed_signature_selects_every_test_of_the_function(tmp_path):
    """A new default value changes every call: both runs, as at function level."""
    new = DISPATCH.replace("def step(self, n):", "def step(self, n=1):")
    selection = _select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))
    assert _selected(selection) == {GDB, LIBDEBUG}
    assert selection.prefixes[GDB] == {"executes Debugger.step (gdb_plus/gdb_plus.py)"}


def test_a_changed_line_no_test_executes_is_reported_with_its_line(tmp_path):
    """Both runs return before `return None`: changing it selects nothing but the unit tier, and says so."""
    new = DISPATCH.replace("return None", "return False")
    selection = _select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))
    assert _selected(selection) == set()
    assert selection.unreached == [f"gdb_plus/gdb_plus.py:{_line(new, 'return False')} (Debugger.step)"]


def test_a_statement_added_where_only_an_unreported_line_ran_selects_the_whole_function(tmp_path):
    """
    A line added just before `while True:` runs where the loop did, but CPython doesn't always report the line of
    `while True:`: no test recorded on it doesn't prove the new line is dead, so every test of the function runs.
    A line added before `return None` runs where that return did: nowhere, it selects nothing.
    """
    index = _dispatch_index(tmp_path)
    new = DISPATCH.replace("        while True:", "        self.waiting = True\n        while True:")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == {GDB, LIBDEBUG}
    new = DISPATCH.replace("        return None", "        self.done = True\n        return None")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == set()


def test_comments_in_an_edited_function_select_nothing_more(tmp_path):
    """A comment edited in the gdb branch, next to a real change in the libdebug branch, doesn't add the gdb run."""
    new = DISPATCH.replace('return "gdb"', 'return "gdb"  # the default').replace("self.libdebug.step(n)", "self.libdebug.step(n + 0)")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=_dispatch_index(tmp_path))) == {LIBDEBUG}


def test_an_index_measured_on_the_new_sources_selects_by_line_too(tmp_path):
    """
    After a rebuild the index holds the lines of the new sources: the change is read from the new side (the libdebug
    branch), and deleting a line selects the tests that ran its neighbours there.
    """
    new = DISPATCH.replace("self.libdebug.step(n)", "self.libdebug.step(n, quiet=True)")
    index = _dispatch_index(tmp_path, new)
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == {LIBDEBUG}
    index = _dispatch_index(tmp_path, DISPATCH.replace("        self.libdebug.step(n)\n", ""))
    new = DISPATCH.replace("        self.libdebug.step(n)\n", "")
    assert _selected(_select("gdb_plus/gdb_plus.py", DISPATCH, new, index=index)) == {LIBDEBUG}


def test_an_index_without_line_data_selects_whole_functions():
    """An index of format 1 (built before the line data existed) still works, by function, and says to rebuild it."""
    selection = _select("gdb_plus/gdb_plus.py", OLD, OLD.replace("return 1", "return 3"))
    assert selection.prefixes["integration/test_control_flow.py::test_step[gdb]"] == \
        {"executes Debugger.step (gdb_plus/gdb_plus.py)"}
    assert any("no line data" in note for note in selection.notes)
