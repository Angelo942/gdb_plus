"""
Checks on the source itself: the public API stays stable, every backend ladder is complete,
and no code path refers to a name that doesn't exist (those only crash when the path runs).
"""
import ast
import builtins
from pathlib import Path

import pytest

import gdb_plus
import gdb_plus.utils
from gdb_plus import Debugger

SOURCE = Path(gdb_plus.__file__).parent / "gdb_plus.py"


@pytest.mark.parametrize("alias, original", [
    ("cont", "c"), ("si", "step"), ("ni", "next"), ("until", "continue_until"), ("breakpoint", "b"),
    ("temporary_breakpoint", "tb"), ("catch", "catch_event"), ("handle_syscall", "catch_syscall"),
    ("setup_remote", "remote"), ("manual", "interrupt"), ("split_on_fork", "set_split_on_fork"),
])
def test_method_aliases(alias, original):
    """Each method alias (c = cont, si = step, until = continue_until...) is the very same function as the original."""
    assert getattr(Debugger, alias) is getattr(Debugger, original)


@pytest.mark.parametrize("alias, original", [
    ("sys_args", "syscall_args"), ("elf", "exe"), ("inferior", "current_inferior"),
    ("elf_address", "base_elf"), ("exe_address", "base_elf"), ("libc_address", "base_libc"),
])
def test_property_aliases(alias, original):
    """Each property alias (base_elf / exe_address...) is the very same property object as the original."""
    assert getattr(Debugger, alias) is getattr(Debugger, original)


@pytest.mark.parametrize("name", ["Debugger", "Structure", "Array", "String", "Inner_Debugger", "SKIP_SYSCALL", "SHOULD_STOP"])
def test_package_exports(name):
    """`from gdb_plus import *` provides the package's own names: Debugger, Structure, Array, String, SKIP_SYSCALL..."""
    namespace = {}
    exec("from gdb_plus import *", namespace)
    assert name in namespace


@pytest.mark.parametrize("name", ["process", "remote", "context", "ELF", "p64", "u64", "log", "args"])
def test_package_reexports_pwntools(name):
    """
    `from gdb_plus import *` also provides pwntools (process, ELF, p64, context...): scripts use it instead of `from pwn
    import *`.
    """
    # Scripts and examples rely on `from gdb_plus import *` replacing `from pwn import *`
    namespace = {}
    exec("from gdb_plus import *", namespace)
    assert name in namespace


def test_syscall_flags_can_be_combined():
    """SKIP_SYSCALL and SHOULD_STOP are distinct bits, so `SKIP_SYSCALL | True` both skips the syscall and stops."""
    assert gdb_plus.SKIP_SYSCALL & gdb_plus.SHOULD_STOP == 0
    assert (gdb_plus.SKIP_SYSCALL | True) & gdb_plus.SHOULD_STOP


def _debugger_class():
    tree = ast.parse(SOURCE.read_text())
    return next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Debugger")


BACKENDS = ["gdb", "libdebug", "new_libdebug"]


def _tested_backend(test):
    """'gdb' for `self.gdb is not None` (also inside `and`/`or`)"""
    if isinstance(test, ast.BoolOp):
        return next((b for b in map(_tested_backend, test.values) if b), None)
    if (isinstance(test, ast.Compare) and isinstance(test.ops[0], ast.IsNot) and isinstance(test.left, ast.Attribute)
            and isinstance(test.left.value, ast.Name) and test.left.value.id == "self" and test.left.attr in BACKENDS):
        return test.left.attr
    return None


def incomplete_backend_ladders():
    """{method: missing backends} for every `if self.gdb ... elif self.libdebug ...` without an else."""
    result = {}
    for function in _debugger_class().body:
        if not isinstance(function, ast.FunctionDef):
            continue
        visited = set()
        for node in ast.walk(function):
            if not isinstance(node, ast.If) or id(node) in visited or not _tested_backend(node.test):
                continue
            chain, current = [], node
            while True:
                visited.add(id(current))
                chain.append(_tested_backend(current.test))
                following = current.orelse
                if len(following) == 1 and isinstance(following[0], ast.If) and _tested_backend(following[0].test):
                    current = following[0]
                else:
                    break
            missing = set(BACKENDS) - set(chain)
            if len(chain) >= 2 and not current.orelse and missing:
                result.setdefault(function.name, set()).update(missing)
    return result


# Deliberate: libdebug falls through to /proc/pid/mem, refuses to split earlier, and has no wait loop
KNOWN_INCOMPLETE_LADDERS = {
    "read": {"libdebug"},
    "write": {"libdebug"},
    "set_split_on_fork": {"libdebug"},
    "_internal_wait": {"libdebug"},
}


def test_backend_ladders_are_complete():
    """
    Golden rule of CLAUDE.md: an action dispatching on the backend must handle all three of them or end
    with `else: raise NotImplementedError`. Otherwise it silently does nothing on the missing one.
    If the gap is on purpose, add it to KNOWN_INCOMPLETE_LADDERS.
    """
    assert incomplete_backend_ladders() == KNOWN_INCOMPLETE_LADDERS


def test_no_undefined_names():
    """
    pyflakes finds no undefined name in gdb_plus: a helper missing from utils/__init__.py would only fail at call time.
    """
    pyflakes = pytest.importorskip("pyflakes.api")
    from pyflakes import messages, reporter

    collected = []

    class Collect(reporter.Reporter):
        def __init__(self):
            pass

        def flake(self, message):
            collected.append(message)

        def unexpectedError(self, filename, message):
            raise AssertionError(message)

        def syntaxError(self, filename, message, line, column, source):
            raise AssertionError(f"{filename}:{line}: {message}")

    pyflakes.check(SOURCE.read_text(), str(SOURCE), Collect())
    # With `from gdb_plus.utils import *` pyflakes can only say "may be undefined": resolve those ourselves
    exported = set(gdb_plus.utils.__all__) | set(dir(builtins))
    undefined = []
    for message in collected:
        if isinstance(message, messages.UndefinedName):
            undefined.append((message.lineno, message.message_args[0]))
        elif isinstance(message, messages.ImportStarUsage) and message.message_args[0] not in exported:
            undefined.append((message.lineno, message.message_args[0]))
    assert undefined == [], "names that raise NameError when their line runs: " + ", ".join(f"line {line}: {name}" for line, name in undefined)
