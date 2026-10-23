"""
Run only the tests that reach what you changed. Loaded by tests/conftest.py.

    pytest --affected -n 8                       the working tree (staged or not) against HEAD
    pytest --affected --affected-ref=staged      what `git commit` would commit (the pre-commit hook, support/pre-commit)
    pytest --affected --affected-ref=main        everything since main

The selection comes from tests/.results/function_tests.json, an index of the tests that execute each line of the
functions of gdb_plus, built by a coverage run whose contexts are the test node ids:

    python3 tests/support/affected.py build -j 5     one pytest per module under coverage (about an hour), then the index
    python3 tests/support/affected.py show [REF]     what --affected would run, and why

A change selects:
    a statement of a function or method of gdb_plus/        the tests that executed it (LineSelection: for an added
                                                            statement, the old one at its place)
    its signature or decorators                             the tests that executed one of its lines
    a module or class level assignment / import             the tests of every function that uses a name it binds
    a class header (bases, decorators)                      the tests of all its methods
    a test function                                         that test, with all its parameters
    a helper of a test module (function, assignment...)    the tests of that module that use it, directly or not
    tests/support, conftest.py, fixtures/, pytest.ini,      the whole suite
    pyproject.toml, any other module level statement
plus the unit tier whenever code changed, and every collected test the index has never seen (added after the build).
Comments and docstrings don't count: definitions are compared by their AST, so moving code doesn't either. An index
of format 1 (no line data) selects every test of a changed function, as do the hunks it can't place.

--affected-baseline (used by the hook) doesn't fail the run for a test whose latest recorded result (in any
tests/.results/<version>.json) is a failure with the same exception type: it is listed, only the new failures (a test
that worked, or fails differently) fail the run.
"""
import argparse
import ast
import difflib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import tokenize
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
RESULTS = Path(os.environ.get("GDB_PLUS_RESULTS_DIR", TESTS / ".results"))
INDEX = RESULTS / "function_tests.json"
COVERAGE_DIR = RESULTS / "coverage"
INDEX_FORMAT = 2         # 1: no line data, still read (selection by function)

# Paths relative to the repository
WHOLE_SUITE = re.compile(r"^(tests/support/(?!pre-(commit|push)$)|tests/fixtures/|tests/pytest\.ini$|pyproject\.toml$|setup\.(py|cfg)$)|(^|/)conftest\.py$")
IGNORED = re.compile(r"\.(md|patch)$|(^|/)\.gitignore$|^tests/support/pre-(commit|push)$|^(docs|examples|\.vscode|\.claude|build|dist)/|^tests/(dashboard|\.results|docker_image[^/]*)/|^[^/]+$")
TEST_MODULE = re.compile(r"^tests/(unit|integration|regression)/(.+/)?test_[^/]*\.py$")
UNIT_TIER = "unit/"


########################## DEFINITIONS ##########################

def _strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return tree


def _bound_names(node):
    """Names a module or class level statement binds, or None if it can't be told (star import, if, try...)"""
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        if any(alias.name == "*" for alias in node.names):
            return None
        return {alias.asname or alias.name.split(".")[0] for alias in node.names}
    targets = {ast.Assign: lambda n: n.targets, ast.AnnAssign: lambda n: [n.target], ast.AugAssign: lambda n: [n.target]}
    for kind, get in targets.items():
        if isinstance(node, kind):
            names = set()
            for target in get(node):
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
                    elif isinstance(sub, ast.Attribute):
                        names.add(sub.attr)
            return names
    return None


class Definitions:
    """
    The functions (qualified name -> AST dump, line range of the body) and the other module and class level statements
    of a source file. Methods are "Class.method"; a function defined inside a function is part of it.
    """
    def __init__(self, source):
        tree = _strip_docstrings(ast.parse(source))
        self.functions = defaultdict(list)    # qualified name -> dumps (a property and its setter share the name)
        self.ranges = defaultdict(list)       # qualified name -> [(first line of the body, last line)]
        self.uses = defaultdict(set)          # qualified name -> names and attributes it reads, and its arguments
        self.classes = {}                     # qualified name -> dump of the header
        self.statements = []                  # (dump, bound names or None)
        self._visit(tree.body, "")

    def _visit(self, body, prefix):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                self.functions[name].append(ast.dump(node))
                # Not the def line nor the decorators: they run when the module is imported, under whatever test imports it
                self.ranges[name].append((node.body[0].lineno, node.end_lineno))
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Name):
                        self.uses[name].add(sub.id)
                    elif isinstance(sub, ast.Attribute):
                        self.uses[name].add(sub.attr)
                    elif isinstance(sub, ast.arg):
                        self.uses[name].add(sub.arg)   # pytest fixtures are arguments
            elif isinstance(node, ast.ClassDef):
                header = ast.ClassDef(name=node.name, bases=node.bases, keywords=node.keywords, body=[],
                                      decorator_list=node.decorator_list)
                self.classes[prefix + node.name] = ast.dump(header)
                self._visit(node.body, prefix + node.name + ".")
            else:
                self.statements.append((ast.dump(node), _bound_names(node)))

    def dump(self, name):
        return "\n".join(self.functions.get(name, []))


def _parse(source, path):
    try:
        return Definitions(source)
    except SyntaxError as e:
        raise SystemExit(f"--affected: can't parse {path}: {e}")


def compare(old, new):
    """
    (functions that changed, classes whose header changed, names bound by changed statements, True if a changed
    statement binds names that can't be told) between two sources, either of which may be None (file added or deleted).
    """
    old = Definitions("") if old is None else old
    new = Definitions("") if new is None else new
    functions = {name for name in set(old.functions) | set(new.functions) if old.dump(name) != new.dump(name)}
    classes = {name for name in set(old.classes) | set(new.classes) if old.classes.get(name) != new.classes.get(name)}
    before, after = Counter(dump for dump, _ in old.statements), Counter(dump for dump, _ in new.statements)
    names, unknown = set(), False
    for dump, bound in old.statements + new.statements:
        if before[dump] != after[dump]:
            if bound is None:
                unknown = True
            else:
                names |= bound
    return functions, classes, names, unknown


########################## LINES ##########################

def _code_lines(text):
    """The lines of a source without comments nor trailing blanks ("" for a line without code): what diffs compare"""
    lines = text.replace("\r\n", "\n").split("\n")
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                row, col = token.start
                lines[row - 1] = lines[row - 1][:col]
    except (tokenize.TokenError, SyntaxError):
        pass
    return [line.rstrip() for line in lines]


def _first_line(node):
    return min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])


def _blocks(node):
    """{field: statements} nested in a statement (an except clause counts as a statement of node.handlers)"""
    blocks = {field: getattr(node, field) for field in ("body", "handlers", "orelse", "finalbody")
              if isinstance(getattr(node, field, None), list)}
    blocks.update({f"case {i}": case.body for i, case in enumerate(getattr(node, "cases", []))})
    return {field: block for field, block in blocks.items() if block}


def _traced(node):
    """Whether executing a statement always reports one of its header lines to coverage"""
    return not _blocks(node) or isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.With, ast.AsyncWith,
                                                  ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))


class _Statement:
    def __init__(self, node, parent, field, siblings, position):
        self.node, self.parent, self.field, self.siblings, self.position = node, parent, field, siblings, position
        self.first, self.end = _first_line(node), node.end_lineno
        blocks = _blocks(node).values()
        # The lines a compound statement runs by itself: up to its first nested statement (if, with, def + decorators...)
        last = max(node.lineno, min(_first_line(block[0]) for block in blocks) - 1) if blocks else self.end
        self.header = range(self.first, last + 1)


class Statements:
    """The statements of a source: the one each line belongs to, and the functions as Definitions names them"""
    def __init__(self, source):
        self.code = _code_lines(source)
        self.at = {}                          # line -> innermost statement containing it
        self.docstrings = set()               # lines of docstrings: no code runs there
        self.functions = defaultdict(list)    # qualified name -> statements of its def
        self.of = {}                          # id of an AST node -> its statement
        self._visit(ast.parse(source).body, None, "body", "", False)

    def _visit(self, body, parent, field, prefix, in_function):
        for position, node in enumerate(body):
            if position == 0 and (parent is None or isinstance(parent.node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                             ast.ClassDef))) \
                    and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str) and body is (parent.node.body if parent else body):
                self.docstrings.update(range(node.lineno, node.end_lineno + 1))
                continue
            statement = self.of[id(node)] = _Statement(node, parent, field, body, position)
            for line in range(statement.first, statement.end + 1):
                self.at[line] = statement
            is_function = isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            if is_function and not in_function:
                self.functions[prefix + node.name].append(statement)
            nested = prefix + node.name + "." if isinstance(node, ast.ClassDef) and not in_function else prefix
            for name, block in _blocks(node).items():
                self._visit(block, statement, name, nested, in_function or is_function)

    def code_lines(self, lines):
        """The lines that hold code, out of lines"""
        return [line for line in lines if self.code[line - 1] and line not in self.docstrings]


def _line_map(old, new):
    """old line -> new line, for the lines the diff of two lists of code lines keeps (1 based)"""
    if old == new:
        return {line: line for line in range(1, len(old) + 1)}
    mapping = {}
    for tag, i1, i2, j1, _ in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == "equal":
            mapping.update({i1 + k + 1: j1 + k + 1 for k in range(i2 - i1)})
    return mapping


class _Direction:
    """
    The tests of the index that can behave differently between measured (the sources the index was measured on, or
    the closest of the two) and other. Lines of the index: built, mapped through a diff when it differs from measured.
    """
    WHOLE = None

    def __init__(self, measured, other, built_code, lines, masks):
        self.old, self.new = measured, other
        self.opcodes = difflib.SequenceMatcher(None, measured.code, other.code, autojunk=False).get_opcodes()
        self.new_to_old = {new: old for old, new in _line_map(measured.code, other.code).items()}
        self.old_to_built = _line_map(measured.code, built_code)
        self.lines, self.masks = lines, masks

    def _anchor(self, statement):
        """The old statement executed by every test that reaches a new one (WHOLE: can't tell)"""
        while statement is not None:
            line = self.new_to_old.get(statement.node.lineno)
            if line is not None:
                return self.old.at.get(line)
            # It runs when the last old statement before it completes, as did the old statement that followed it
            for previous in reversed(statement.siblings[:statement.position]):
                line = self.new_to_old.get(previous.lineno)
                if line is not None and self.old.at.get(line) is not None:
                    before = self.old.at[line]
                    after = before.siblings[before.position + 1:]
                    return self.old.of[id(after[0])] if after else before
            # Only new statements before it in its block: it runs when the block is entered, as did the first old one
            parent = statement.parent
            line = None if parent is None else self.new_to_old.get(parent.node.lineno)
            if line is not None and self.old.at.get(line) is not None:
                old_parent = self.old.at[line]
                if statement.field.startswith("case"):   # the old case of that number may be another one
                    return old_parent
                block = [node for node in _blocks(old_parent.node).get(statement.field, []) if id(node) in self.old.of]
                return self.old.of[id(block[0])] if block else old_parent    # a new else, except...: its header
            statement = parent
        return self.WHOLE

    def _tests(self, statements):
        """Bit mask of the tests that executed one of the header lines of statements, None if a line isn't indexed"""
        mask = 0
        for statement in statements:
            for line in self.old.code_lines(statement.header):
                built = self.old_to_built.get(line)
                if built is None:
                    return None
                index = self.lines.get(str(built))
                if index is not None:
                    mask |= int(self.masks[index], 16)
        return mask

    def hunks(self, function):
        """[(old code lines, new code lines, i1, j1, bit mask of the tests)] of a function, None: the whole function"""
        old_defs, new_defs = self.old.functions.get(function), self.new.functions.get(function)
        if not old_defs or not new_defs:
            return None

        def inside(line, defs, body):
            return any((_first_line(s.node.body[0]) if body else s.first) <= line <= s.end for s in defs)

        result = []
        for tag, i1, i2, j1, j2 in self.opcodes:
            if tag == "equal":
                continue
            old_lines = [line for line in self.old.code_lines(range(i1 + 1, i2 + 1)) if inside(line, old_defs, False)]
            new_lines = [line for line in self.new.code_lines(range(j1 + 1, j2 + 1)) if inside(line, new_defs, False)]
            if not old_lines and not new_lines:
                continue
            # The signature or a decorator: it changes every call
            if not all(inside(line, old_defs, True) for line in old_lines) \
                    or not all(inside(line, new_defs, True) for line in new_lines):
                return None
            changed = {self.old.at[line] for line in old_lines}
            anchors = {self._anchor(self.new.at[line]) for line in new_lines} - changed
            if self.WHOLE in anchors or (changed | anchors) & set(old_defs):
                return None
            mask = 0
            for statement in changed | anchors:
                tests = self._tests([statement])
                # No test executed it: dead code, unless its line may not be reported (while True:, try:...)
                if tests is None or tests == 0 and not _traced(statement.node):
                    return None
                mask |= tests
            result.append((old_lines, new_lines, i1, j1, mask))
        return result


class LineSelection:
    """
    Line level selection in one file of gdb_plus: the tests that executed the statements a diff touches.
        a changed or deleted statement      the tests that executed it (for a compound statement, its header)
        an added statement                  the tests that executed the old statement at its place: the one after the
                                            last old statement before it in its block (that one if it was the last),
                                            the first of the block if it comes first (an added clause: the header of
                                            its if, try...)
        the signature or the decorators     every test of the function, as when the index can't tell
    A test that runs none of them goes through the same statements in both versions. The rule is symmetric: the
    index may have been measured on the old sources (built before the change) or on the new ones (rebuilt since),
    or on others, mapped through a diff, as long as the lines a hunk needs didn't change between them.
    """
    def __init__(self, old_source, new_source, built_source, lines, masks):
        old, new, built = Statements(old_source), Statements(new_source), _code_lines(built_source)
        forward = lambda: _Direction(old, new, built, lines, masks)
        backward = lambda: _Direction(new, old, built, lines, masks)
        self._directions = [(backward, True), (forward, False)] if built == new.code else \
            [(forward, False), (backward, True)]
        self._built = {}

    def _direction(self, i):
        if i not in self._built:
            self._built[i] = self._directions[i][0]()
        return self._built[i], self._directions[i][1]

    def hunks(self, function):
        """[(label of the changed lines of the new sources, test ids)] of a function, None: the whole function"""
        for i in range(len(self._directions)):
            direction, swapped = self._direction(i)
            hunks = direction.hunks(function)
            if hunks is None:
                continue
            result = []
            for old_lines, new_lines, i1, j1, mask in hunks:
                lines, position = (old_lines, i1) if swapped else (new_lines, j1)
                if lines:
                    label = f"{lines[0]}" if lines[0] == lines[-1] else f"{lines[0]}-{lines[-1]}"
                else:
                    label = f"{position} (lines deleted below it)"
                result.append((label, [i for i in range(mask.bit_length()) if mask >> i & 1]))
            return result
        return None


########################## SELECTION ##########################

def _git(*args, binary=False):
    result = subprocess.run(["git", *args], cwd=REPO, capture_output=True)
    if result.returncode != 0:
        return None
    return result.stdout if binary else result.stdout.decode(errors="replace")


def changed_files(ref):
    """[(path relative to the repository, old source or None, new source or None)]. ref: "staged" or a revision"""
    if ref == "staged":
        names = _git("diff", "--cached", "--name-only", "--no-renames", "-z")
        old_rev, new = "HEAD", lambda path: _git("show", f":{path}")
    else:
        names = _git("diff", ref, "--name-only", "--no-renames", "-z")
        untracked = _git("ls-files", "--others", "--exclude-standard", "-z") or ""
        names = None if names is None else names + untracked
        old_rev = ref

        def new(path):
            try:
                return (REPO / path).read_text(errors="replace")
            except OSError:
                return None
    if names is None:
        raise SystemExit(f"--affected: git can't compare against {ref!r}")
    files = []
    for path in sorted(set(filter(None, names.split("\0")))):
        if path.endswith(".py"):
            files.append((path, _git("show", f"{old_rev}:{path}"), new(path)))
        else:
            files.append((path, None, None))
    return files


class Selection:
    """What to run: everything, or the tests named by node id or node id prefix, each with the reasons"""
    def __init__(self):
        self.everything = []                 # reasons to run the whole suite
        self.prefixes = defaultdict(set)     # node id or prefix -> reasons
        self.unreached = []                  # changed functions no test executes
        self.notes = []
        self.code_changed = False
        self.new_tests = True                # also run the collected tests that the index doesn't know

    def add(self, prefix, reason):
        self.prefixes[prefix].add(reason)

    def matches(self, nodeid):
        """The reasons that select a node id (empty: not selected)"""
        if self.everything:
            return set(self.everything)
        reasons = set()
        for prefix, why in self.prefixes.items():
            if nodeid == prefix or nodeid.startswith(prefix if prefix.endswith("/") else prefix + "::") \
                    or nodeid.startswith(prefix + "["):
                reasons |= why
        return reasons

    def selects(self, nodeid, known=None):
        """Whether to run a collected test. known: the node ids the index has seen (None: no index)"""
        if self.matches(nodeid):
            return True
        return known is not None and self.code_changed and nodeid not in known

    def __bool__(self):
        return bool(self.everything or self.prefixes)


def load_index(path=INDEX):
    try:
        index = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return index if index.get("format") in (1, INDEX_FORMAT) else None


def _package_definitions():
    """Definitions of every gdb_plus/**/*.py of the working tree, by path relative to the repository"""
    result = {}
    for path in sorted((REPO / "gdb_plus").rglob("*.py")):
        try:
            result[str(path.relative_to(REPO))] = Definitions(path.read_text())
        except (OSError, SyntaxError):
            continue
    return result


def _module_closure(definitions, names):
    """Test functions of a module that use one of names, directly or through other functions of the module"""
    names, grew = set(names), True
    while grew:
        grew = False
        for function, uses in definitions.uses.items():
            short = function.split(".")[-1]
            if short not in names and uses & names:
                names.add(short)
                grew = True
    return {f for f in definitions.functions if f.split(".")[-1] in names and f.split(".")[-1].startswith("test")}


def select(ref="HEAD", index=None, files=None, package=None):
    """
    The Selection for the changes against ref ("staged" for the index of git). files: changed_files(ref) already
    computed; package: the Definitions of gdb_plus/ by path (default: the working tree)
    """
    selection = Selection()
    files = changed_files(ref) if files is None else files
    functions_index = (index or {}).get("functions", {})
    tests = (index or {}).get("tests", [])
    for path, old_source, new_source in files:
        if IGNORED.search(path) and not WHOLE_SUITE.search(path):
            continue
        if WHOLE_SUITE.search(path):
            selection.everything.append(f"{path} changed: it can affect every test")
            continue
        if path.startswith("gdb_plus/"):
            if not path.endswith(".py"):
                selection.everything.append(f"{path} changed: not Python, can't tell which tests use it")
                continue
            old = None if old_source is None else _parse(old_source, path)
            new = None if new_source is None else _parse(new_source, path)
            functions, classes, names, unknown = compare(old, new)
            selection.code_changed |= bool(functions or classes or names or unknown)
            if unknown:
                selection.everything.append(f"{path}: a module or class level statement changed (import *, if, try...)")
                continue
            edited = set(functions)
            whole = set()              # users of a changed name, methods of a changed class: every test of the function
            if names:
                package = _package_definitions() if package is None else package
                for file, definitions in package.items():
                    users = {f for f, uses in definitions.uses.items() if uses & names}
                    functions |= {(file, f) for f in users}
                    whole |= users if file == path else set()
            for name in classes:
                for definitions in filter(None, [old, new]):
                    methods = {f for f in definitions.functions if f.startswith(name + ".")}
                    functions |= methods
                    whole |= methods
            lines = None
            if old is not None and new is not None and path in (index or {}).get("lines", {}) \
                    and path in index.get("texts", {}):
                lines = LineSelection(old_source, new_source, index["texts"][path], index["lines"][path], index["masks"])
            for function in sorted(functions, key=str):
                file, function = function if isinstance(function, tuple) else (path, function)
                key = f"{file}::{function}"
                hunks = lines.hunks(function) if lines is not None and file == path and function in edited \
                    and function not in whole else None
                if hunks is not None:
                    for label, ids in hunks:
                        if not ids:
                            selection.unreached.append(f"{file}:{label} ({function})")
                        for i in ids:
                            selection.add(tests[i], f"executes {file}:{label} ({function})")
                    continue
                ids = functions_index.get(key)
                if not ids and index is not None:
                    selection.unreached.append(key)
                for i in ids or []:
                    selection.add(tests[i], f"executes {function} ({file})")
            continue
        if TEST_MODULE.match(path):
            module = path[len("tests/"):]
            old = None if old_source is None else _parse(old_source, path)
            new = None if new_source is None else _parse(new_source, path)
            if new is None:
                continue
            functions, classes, names, unknown = compare(old, new)
            selection.code_changed |= bool(functions or classes or names or unknown)
            if unknown or classes or "pytestmark" in names:
                selection.add(module, f"{module}: a module level statement changed")
                continue
            names |= {f.split(".")[-1] for f in functions}
            for test in _module_closure(new, names):
                selection.add(f"{module}::{test.replace('.', '::')}", f"{module}::{test} or a helper it uses changed")
            continue
        if path.startswith("tests/"):
            selection.everything.append(f"{path} changed: a file the tests may read")
    if selection.code_changed:
        selection.add(UNIT_TIER, "the unit tier runs on every code change")
    if index is None and selection.code_changed and not selection.everything:
        selection.everything.append(f"no index of the tests per function ({INDEX.relative_to(REPO)}): "
                                    f"build it with python3 tests/support/affected.py build")
    if index is not None and "lines" not in index and selection.code_changed:
        selection.notes.append("the index has no line data (format 1): a changed function selects all its tests, "
                               "rebuild it to select by line (python3 tests/support/affected.py build)")
    if index is not None:
        stale = [file for file, digest in index.get("sources", {}).items()
                 if hashlib.sha256((_git("show", f"HEAD:{file}", binary=True) or b"")).hexdigest() != digest]
        if stale:
            selection.notes.append(f"the index was built on {time.strftime('%d %b %H:%M', time.localtime(index['built']))} "
                                   f"from sources that differ from HEAD ({', '.join(stale)}): rebuild it when "
                                   f"functions moved between tests (python3 tests/support/affected.py build)")
    return selection


def describe(selection, index, ref):
    """What a Selection will run, one line per reason"""
    lines = [f"--affected against {ref}:"]
    if selection.everything:
        lines += [f"  whole suite: {reason}" for reason in selection.everything]
    elif not selection:
        lines.append("  no change to code or tests: nothing to run")
    else:
        reasons = Counter(reason for why in selection.prefixes.values() for reason in why)
        lines += [f"  {count:5} tests or modules: {reason}" for reason, count in sorted(reasons.items())]
        if index:
            lines.append("  and the collected tests the index doesn't know (added after it was built)")
    lines += [f"  no test executes {key}" for key in selection.unreached]
    lines += [f"  note: {note}" for note in selection.notes]
    return lines


########################## PYTEST PLUGIN ##########################

def _exception_type(message):
    """'TypeError' of 'TypeError: unsupported operand...': what a failure is compared on (messages hold addresses)"""
    first = (message or "").strip().splitlines()[0] if (message or "").strip() else ""
    return first.split(":", 1)[0].strip()


def pytest_addoption(parser):
    group = parser.getgroup("gdb_plus")
    group.addoption("--affected", action="store_true",
                    help="only run the tests that reach the changed code (tests/support/affected.py)")
    group.addoption("--affected-ref", default="HEAD", metavar="REF",
                    help="compare the working tree with this revision, or 'staged' for what git commit would commit. "
                         "Default: HEAD")
    group.addoption("--affected-baseline", action="store_true",
                    help="don't fail for tests whose last recorded result was already a failure")
    group.addoption("--coverage-contexts", action="store_true",
                    help="under `coverage run`: label the lines with the node id of the test and save after each test "
                         "(how the index of --affected is built)")


def pytest_configure(config):
    if config.getoption("--coverage-contexts"):
        config.pluginmanager.register(CoverageContexts(), "gdb_plus_coverage_contexts")
    if config.getoption("--affected"):
        config.pluginmanager.register(Affected(config), "gdb_plus_affected")


class CoverageContexts:
    @staticmethod
    def _coverage():
        import coverage
        return coverage.Coverage.current()

    def pytest_runtest_setup(self, item):
        cov = self._coverage()
        if cov is not None:
            cov.switch_context(item.nodeid)

    def pytest_runtest_logfinish(self, nodeid, location):
        # The watchdog of conftest.py may _exit on a hang: what was saved survives
        cov = self._coverage()
        if cov is not None:
            cov.save()


class Affected:
    def __init__(self, config):
        self.config = config
        self.index = load_index()
        self.selection = select(config.getoption("--affected-ref"), self.index)
        self.known = set(self.index.get("collected", [])) if self.index else set()
        self.failed = {}                 # node id -> exception type of its failure
        self.already_failing = {}        # node id -> exception type of its latest recorded failure
        if config.getoption("--affected-baseline") and not hasattr(config, "workerinput"):
            self.already_failing = self._recorded_failures()

    def _recorded_failures(self):
        """
        The latest recorded result of every test, across the results files: the version in pyproject.toml isn't
        always the one the runs are recorded under (--record-as). Restricted to that file when --record-as is given.
        """
        flavor = self.config.getoption("--gdb-flavor")
        record_as = self.config.getoption("--record-as")
        paths = [RESULTS / f"{record_as}.json"] if record_as else sorted(RESULTS.glob("*.json"))
        latest = {}
        for path in paths:
            try:
                results = json.loads(path.read_text()).get("results")
            except (OSError, ValueError, AttributeError):
                continue
            if not isinstance(results, dict):
                continue
            for key, entry in results.items():
                if not key.startswith(flavor + "|") or not isinstance(entry, dict):
                    continue
                nodeid = key.split("|", 1)[1]
                if entry.get("when", 0) >= latest.get(nodeid, {}).get("when", 0):
                    latest[nodeid] = entry
        return {nodeid: _exception_type(entry.get("message", "")) for nodeid, entry in latest.items()
                if entry.get("status") == "failing"}

    def pytest_sessionstart(self, session):
        # Not pytest_report_header: -q (the hook) hides it, and a long run should say upfront why it is long
        reporter = self.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None and not hasattr(self.config, "workerinput"):
            for line in describe(self.selection, self.index, self.config.getoption("--affected-ref")):
                reporter.write_line(line)

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        if self.selection.everything:
            return
        selected, deselected = [], []
        known = self.known if self.index else None
        for item in items:
            if self.selection.selects(item.nodeid, known):
                selected.append(item)
            else:
                deselected.append(item)
        if deselected:
            config.hook.pytest_deselected(items=deselected)
            items[:] = selected

    def pytest_runtest_logreport(self, report):
        if report.failed and report.nodeid not in self.failed:
            from support.results import _crash_message
            self.failed[report.nodeid] = _exception_type(_crash_message(report))

    def _new_failures(self):
        return sorted(nodeid for nodeid, kind in self.failed.items() if self.already_failing.get(nodeid) != kind)

    def pytest_sessionfinish(self, session, exitstatus):
        if self.config.getoption("--affected-baseline") and self.failed and not self._new_failures() \
                and exitstatus == 1:
            session.exitstatus = 0

    def pytest_terminal_summary(self, terminalreporter):
        if not self.config.getoption("--affected-baseline") or not self.failed:
            return
        new = self._new_failures()
        old = sorted(set(self.failed) - set(new))
        if old:
            terminalreporter.write_line(f"--affected-baseline: {len(old)} failures were already recorded, with the same "
                                        f"exception, they don't fail the run:")
            for nodeid in old:
                terminalreporter.write_line(f"    {nodeid}  ({self.failed[nodeid]})")
        if new:
            terminalreporter.write_line(f"--affected-baseline: {len(new)} new failures (recorded working, or failing "
                                        f"with another exception):", red=True)
            for nodeid in new:
                was = self.already_failing.get(nodeid)
                terminalreporter.write_line(f"    {nodeid}  ({self.failed[nodeid]}"
                                            + (f", recorded: {was})" if was else ")"), red=True)


########################## INDEX ##########################

def _sources_digest(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / "gdb_plus").rglob("*.py"))}


def _tree_digest(root):
    files = sorted((root / "gdb_plus").rglob("*.py")) + sorted((root / "tests").rglob("*.py"))
    return hashlib.sha256(b"".join(p.read_bytes() for p in files if "__pycache__" not in p.parts)).hexdigest()


def build_index(data, root, collected):
    """The index from a coverage.CoverageData whose contexts are node ids, for the sources under root"""
    root = Path(root).resolve()
    tests, functions = {}, defaultdict(set)
    masks, lines, texts = {}, defaultdict(dict), {}     # bit mask of test ids -> its index; file -> line -> mask index
    for measured in data.measured_files():
        try:
            file = str(Path(measured).resolve().relative_to(root))
        except ValueError:
            continue
        by_line = data.contexts_by_lineno(measured)
        texts[file] = Path(measured).read_text()
        definitions = Definitions(texts[file])
        for name, ranges in definitions.ranges.items():
            for start, end in ranges:
                for line in range(start, end + 1):
                    mask = 0
                    for context in by_line.get(line, ()):
                        if context:
                            mask |= 1 << tests.setdefault(context, len(tests))
                    if mask:
                        functions[f"{file}::{name}"].update(i for i in range(mask.bit_length()) if mask >> i & 1)
                        lines[file][str(line)] = masks.setdefault(mask, len(masks))
    order = sorted(tests, key=tests.get)
    return {
        "format": INDEX_FORMAT,
        "built": time.time(),
        "sources": _sources_digest(root),
        "tests": order,
        "collected": sorted(collected),
        "functions": {name: sorted(ids) for name, ids in sorted(functions.items())},
        # The tests that executed each line of a function body, and the sources it was measured on (LineSelection)
        "masks": [format(mask, "x") for mask in sorted(masks, key=masks.get)],
        "lines": {file: dict(sorted(by_line.items(), key=lambda item: int(item[0]))) for file, by_line in lines.items()},
        "texts": texts,
    }


def _collect(tests_dir, pythonpath):
    env = dict(os.environ, PYTHONPATH=pythonpath)
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-record", "-p", "no:cacheprovider"],
                         cwd=tests_dir, capture_output=True, text=True, env=env).stdout
    return [line.strip() for line in out.splitlines() if "::" in line]


def _run_coverage(jobs, scale):
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    for old in COVERAGE_DIR.glob(".coverage*"):
        old.unlink()
    rc = COVERAGE_DIR / "rc"
    rc.write_text(f"[run]\nsource = gdb_plus\ndata_file = {COVERAGE_DIR / '.coverage'}\nparallel = True\n"
                  f"concurrency = thread,multiprocessing\n")
    modules = sorted([*map(str, (TESTS / "integration").glob("test_*.py")), *map(str, (TESTS / "regression").glob("test_*.py"))],
                     key=lambda m: -Path(m).stat().st_size)
    modules = [str(Path(m).relative_to(TESTS)) for m in modules] + ["unit"]

    def run(module):
        log = COVERAGE_DIR / (module.replace("/", "_") + ".log")
        start = time.time()
        with open(log, "w") as out:
            try:
                status = subprocess.run([sys.executable, "-m", "coverage", "run", f"--rcfile={rc}", "-m", "pytest", module,
                                         "-q", "--no-record", "-p", "no:cacheprovider", "--coverage-contexts",
                                         f"--timeout-scale={scale}"], cwd=TESTS, stdout=out, stderr=subprocess.STDOUT,
                                        timeout=3600).returncode
            except subprocess.TimeoutExpired:
                status = "timeout"
        print(f"  {module}: exit {status} in {time.time() - start:.0f}s (log: {log})", flush=True)

    print(f"running {len(modules)} modules under coverage, {jobs} at a time", flush=True)
    with ThreadPoolExecutor(jobs) as pool:
        list(pool.map(run, modules))
    import coverage
    cov = coverage.Coverage(data_file=str(COVERAGE_DIR / ".coverage"))
    cov.combine()
    cov.save()
    return cov.get_data()


def _main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="run the suite under coverage and write the index")
    build.add_argument("-j", "--jobs", type=int, default=4, help="test modules run at the same time (default 4)")
    build.add_argument("--timeout-scale", type=float, default=2, help="passed to pytest (default 2: coverage is slower)")
    build.add_argument("--from", dest="data", metavar="DATA",
                       help="don't run anything: build from this coverage data file (contexts = node ids)")
    build.add_argument("--root", default=str(REPO),
                       help="with --from: the copy of the repository the data was measured on (default: this one)")
    build.add_argument("--out", default=str(INDEX))
    show = sub.add_parser("show", help="print what --affected would run")
    show.add_argument("ref", nargs="?", default="HEAD", help="revision, or 'staged' (default HEAD)")
    show.add_argument("--list", action="store_true", help="also print every selected node id with its reasons")
    args = parser.parse_args()

    if args.command == "show":
        index = load_index()
        selection = select(args.ref, index)
        for line in describe(selection, index, args.ref):
            print(line)
        if args.list and not selection.everything:
            for prefix, reasons in sorted(selection.prefixes.items()):
                print(f"{prefix}    <- {'; '.join(sorted(reasons))}")
        return

    import coverage
    root = Path(args.root).resolve()
    if args.data:
        cov = coverage.Coverage(data_file=args.data)
        cov.load()
        data = cov.get_data()
    else:
        before = _tree_digest(root)
        data = _run_coverage(args.jobs, args.timeout_scale)
        if _tree_digest(root) != before:
            raise SystemExit("gdb_plus/ or tests/ changed during the run: the lines don't match the sources, rerun it")
    print("collecting the node ids", flush=True)
    collected = _collect(root / "tests", str(root))
    index = build_index(data, root, collected)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(index))
    print(f"{args.out}: {len(index['functions'])} functions, {len(index['tests'])} tests that reach gdb_plus, "
          f"{len(collected)} collected")


if __name__ == "__main__":
    sys.path.insert(0, str(TESTS))
    _main()
