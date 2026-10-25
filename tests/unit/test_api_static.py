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

# The Debugger is split in one module per feature area (gdb_plus/debugger/), with one Backend per engine (engines/)
SOURCES = sorted((Path(gdb_plus.__file__).parent / "debugger").rglob("*.py"))


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


def _debugger_methods():
    """The methods of every class of the Debugger package: Debugger, its mixins and PtraceEmulator"""
    for source in SOURCES:
        for node in ast.parse(source.read_text()).body:
            if isinstance(node, ast.ClassDef):
                yield from node.body


BACKENDS = ["gdb", "libdebug", "new_libdebug"]


def _tested_backend(test):
    """'gdb' for `self.gdb is not None` (also inside `and`/`or`)"""
    if isinstance(test, ast.BoolOp):
        return next((b for b in map(_tested_backend, test.values) if b), None)
    if (isinstance(test, ast.Compare) and isinstance(test.ops[0], ast.IsNot) and isinstance(test.left, ast.Attribute)
            and isinstance(test.left.value, ast.Name) and test.left.value.id == "self" and test.left.attr in BACKENDS):
        return test.left.attr
    return None


def backend_ladders():
    """{method} of the Debugger with an `if self.gdb ... elif self.libdebug ...` on two engines or more"""
    result = set()
    for function in _debugger_methods():
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
            if len(chain) >= 2:
                result.add(function.name)
    return result


ENGINE_CLASSES = {"gdb": "GdbBackend", "libdebug": "LibdebugBackend", "new_libdebug": "NewLibdebugBackend"}


def _engine_classes():
    """{class name: ClassDef} of gdb_plus/debugger/engines/"""
    classes = {}
    for source in SOURCES:
        if source.parent.name == "engines":
            for node in ast.parse(source.read_text()).body:
                if isinstance(node, ast.ClassDef):
                    classes[node.name] = node
    return classes


def _only_raises(function):
    """The method only raises (NotImplementedError, or the Exception("not supported") of the 128 bit registers)"""
    body = function.body[1:] if ast.get_docstring(function) is not None else function.body
    return len(body) == 1 and isinstance(body[0], ast.Raise)


def inherited_defaults():
    """{method: engines} for every Backend method that does something an engine inherits instead of overriding it."""
    classes = _engine_classes()
    result = {}
    for function in classes["Backend"].body:
        if not isinstance(function, ast.FunctionDef) or function.name.startswith("__") or function.decorator_list:
            continue
        if _only_raises(function):
            continue
        for engine, name in ENGINE_CLASSES.items():
            defined = {n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id
                       for n in classes[name].body if isinstance(n, (ast.FunctionDef, ast.Assign))}
            if function.name not in defined:
                result.setdefault(function.name, set()).add(engine)
    return result


# Deliberate: the engine has no version of its own, and what Backend does is right for it
KNOWN_INHERITED_DEFAULTS = {
    "internal_wait": {"libdebug"}, # legacy libdebug has no wait loop: it calls handle_stop itself
    "read": {"libdebug"}, # /proc/pid/mem
    "write": {"libdebug"}, # /proc/pid/mem
    "auxiliary_vector": {"gdb"}, # `info auxv`, also without an engine
    "stop_splitting": {"libdebug"}, # set_split_on_fork refuses legacy libdebug before
    "start_splitting": {"libdebug"}, # set_split_on_fork refuses legacy libdebug before
    "call_mprotect": {"libdebug", "new_libdebug"}, # call() of the mprotect of the process
    "catch_pending_sigint": {"libdebug", "new_libdebug"}, # only gdb leaves a SIGINT pending
    "handle_signal": {"libdebug", "new_libdebug"}, # only gdb needs a command
    "close": {"libdebug", "new_libdebug"}, # only gdb has something to release
    "repr": {"gdb", "libdebug"}, # the Debugger's own representation
    "clear_register_cache": {"libdebug", "new_libdebug"}, # only gdb caches the registers
}


def test_backends_are_complete():
    """
    Golden rule of CLAUDE.md, for the Backend classes: a Backend method either only raises (NotImplementedError), so that
    an engine without its own version fails loudly, or does something on purpose for the engines listed in
    KNOWN_INHERITED_DEFAULTS. Otherwise an engine silently gets a behaviour meant for another case.
    """
    assert inherited_defaults() == KNOWN_INHERITED_DEFAULTS


def test_no_backend_ladders():
    """
    Golden rule of CLAUDE.md: what differs between the engines is a method of each Backend (engines/), reached through
    self._backend, which the setters of dbg.gdb, dbg.libdebug and dbg.new_libdebug set. The only engine ladder left is
    Debugger.__getattr__, which hands the names it doesn't know to the engine objects (dbg.gdb, dbg.libdebug...).
    """
    assert backend_ladders() == {"__getattr__"}


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

    for source in SOURCES:
        pyflakes.check(source.read_text(), str(source), Collect())
    # With `from gdb_plus.utils import *` pyflakes can only say "may be undefined": resolve those ourselves
    exported = set(gdb_plus.utils.__all__) | set(dir(builtins))
    undefined = []
    for message in collected:
        if isinstance(message, messages.UndefinedName):
            undefined.append((message.filename, message.lineno, message.message_args[0]))
        elif isinstance(message, messages.ImportStarUsage) and message.message_args[0] not in exported:
            undefined.append((message.filename, message.lineno, message.message_args[0]))
    assert undefined == [], "names that raise NameError when their line runs: " + ", ".join(f"{Path(file).name}:{line}: {name}" for file, line, name in undefined)


# What each object of the Debugger reads or calls on its Debugger (self.dbg, read as dbg): its whole dependency on the rest.
# The address space and the controller need little; the backends drive the Debugger's own actions (step, b, cont...)
# from their stop policies. A new name here is a new dependency: prefer a method of the object itself when it can do the job.
DEBUGGER_NAMES = {
    "Backend": {"_context_params", "_initialized", "call", "control", "execute", "pid"},
    "GdbBackend": {"_details_breakpoint_stopped", "_forget_breakpoint", "_gef", "_hidden_continue", "_internal_wait",
                   "_interrupt_inner", "_pwndbg", "_silence", "_split_child", "_step", "_stop_reason", "_write_qemu_host",
                   "b", "children", "conn", "cont", "control", "current_inferior", "execute", "execute_action",
                   "fork_handler", "gdb", "gdb_call", "gdbscript", "inferior_from_pid", "instruction_pointer", "jump",
                   "local_debugging", "logger", "make_page_rwx", "next_inst", "pid", "ptrace", "return_value",
                   "reverse_lookup", "running", "signal", "split", "step"},
    "LibdebugBackend": {"_detached", "_find_rip", "_hidden_continue", "_stop_reason", "c", "call", "cont", "control",
                        "execute_action", "instruction_pointer", "libdebug", "logger", "pid", "ptrace", "reverse_lookup",
                        "step", "stop_signal"},
    "NewLibdebugBackend": {"_find_rip", "_forget_breakpoint", "_internal_wait", "_stop_reason", "c", "cont", "control",
                           "execute_action", "instruction_pointer", "logger", "new_libdebug", "pid", "ptrace",
                           "reverse_lookup", "si", "step", "stop_signal"},
    # libs: the Debugger it starts to read the libraries of a process it doesn't debug
    "AddressSpace": {"_context_params", "_initialized", "_raw_maps", "debugging", "download", "execute", "gdb", "libc", "libs",
                     "local_debugging", "logger", "pid"},
    "Controller": {"_backend", "_context_params", "_hidden_continue", "_initialized", "debugging", "delete_breakpoint",
                   "instruction_pointer", "logger", "pid", "ptrace", "return_value"},
    "PtraceEmulator": {"_parent", "_parse_address", "_process_group", "_stop_reason", "args", "b", "catch_syscall", "children",
                       "control", "delete_breakpoint", "delete_catch_syscall", "execute", "gdb", "logger", "new_libdebug",
                       "pid", "read", "return_value", "stop_signal", "symbols", "syscall_args", "write"},
}

def debugger_names_used():
    """{class: names read on dbg / self.dbg} for the classes of DEBUGGER_NAMES"""
    used = {}
    for source in SOURCES + sorted((Path(gdb_plus.__file__).parent / "debugger" / "engines").glob("*.py")):
        for cls in ast.parse(source.read_text()).body:
            if not isinstance(cls, ast.ClassDef) or cls.name not in DEBUGGER_NAMES:
                continue
            names = used.setdefault(cls.name, set())
            for node in ast.walk(cls):
                if not isinstance(node, ast.Attribute):
                    continue
                value = node.value
                if isinstance(value, ast.Name) and value.id == "dbg":
                    names.add(node.attr)
                elif (isinstance(value, ast.Attribute) and value.attr == "dbg" and isinstance(value.value, ast.Name)
                      and value.value.id == "self"):
                    names.add(node.attr)
    return used

def test_objects_use_declared_debugger_names():
    """
    The backends, the address space, the controller and the ptrace emulator reach their Debugger (self.dbg) only for the
    names listed in DEBUGGER_NAMES: a new dependency on the Debugger is a decision, not an accident.
    """
    assert debugger_names_used() == DEBUGGER_NAMES

# Private names of the Debugger each mixin uses without defining them: the state of DebuggerBase, or a private method of
# another mixin. The helpers over the public API (memory, calls, events, registers, stepping, gef, bruteforce) should
# only shrink this list.
MIXIN_PRIVATE_NAMES = {
    "memory": {"_backend", "_canary", "_exe", "_free_bss", "_parse_address", "_raw_maps", "_saved_auxiliary_vector"},
    "calls": {"_backend", "_exe", "_parse_address"},
    "events": {"_backend", "_exe", "_ftrace_breakpoints", "_ltrace_breakpoints"},
    "registers": {"_args", "_backend", "_capstone", "_sys_args"},
    "stepping": {"_backend", "_find_rip", "_interrupt_inner", "_parse_address", "_saved_ip", "_stop_reason"},
    "gef": {"_gef", "_pwndbg"},
    "bruteforce": {"_parse_address", "_stop_reason"},
    "breakpoints": {"_backend"},
    "files": set(),
    "forks": {"_backend", "_exe", "_gef", "_parent", "_pwndbg"},
    "launch": {"_backend", "_backend_of", "_backup_p", "_detached", "_exe", "_host", "_parse_address", "_port"},
    "control_flow": {"_backend", "_parse_address"},
    "stops": {"_backend"},
    "backends": {"_backend", "_backends", "_detached", "_exe", "_gef", "_pwndbg"},
}

def mixin_private_names():
    """{module: private names read on self that its mixin doesn't define} for the modules of MIXIN_PRIVATE_NAMES"""
    out = {}
    for source in SOURCES:
        if source.stem not in MIXIN_PRIVATE_NAMES:
            continue
        tree = ast.parse(source.read_text())
        mixin = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name.endswith("Mixin"))
        own = {node.name for node in mixin.body if isinstance(node, ast.FunctionDef)}
        out[source.stem] = {node.attr for node in ast.walk(mixin)
                            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self"
                            and node.attr.startswith("_") and not node.attr.startswith("__") and node.attr not in own}
    return out

def test_mixins_use_declared_private_names():
    """
    A mixin reaches the private names of the others (or of DebuggerBase) only for the ones listed in MIXIN_PRIVATE_NAMES:
    the feature areas stay coupled through the public API of the Debugger and through these names only.
    """
    assert mixin_private_names() == MIXIN_PRIVATE_NAMES
