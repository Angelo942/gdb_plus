import subprocess

import pytest

from support.results import QEMU_ARCHES, expand

# The target axis: every feature test that takes the `backend` fixture runs once per target.
#   gdb, libdebug, new_libdebug   the x86-64 fixture, started with gdb then migrated to the backend
#   remote                        the x86-64 fixture under gdbserver, debugged through Debugger((host, port))
#   i386                          the fixture built with -m32, native gdb
#   arm ... mips64                the freestanding fixture (fixtures/src/freestanding.h) under qemu-user
#   aarch64_remote                the fixture built on the arm64 machine of --remote-gdbserver, run there under gdbserver
#                                 and debugged from here (support/remote_host.py). Deselected without the option
# A target that can't run a test is declared on the test (or the module) with
# @pytest.mark.not_applicable / untested / known_gap(target or group, reason): see support/results.py.
TARGETS = ["gdb", "libdebug", "new_libdebug", "remote", "i386", *QEMU_ARCHES, "aarch64_remote"]


def _target(name):
    marks = []
    if name in ["libdebug", "new_libdebug"]:
        marks.append(getattr(pytest.mark, name))
    elif name in QEMU_ARCHES:
        marks.append(pytest.mark.qemu(name))
    elif name == "aarch64_remote":
        marks.append(pytest.mark.remote_gdbserver)
    return pytest.param(name, id=name, marks=marks)


@pytest.fixture(params=[_target(name) for name in TARGETS])
def backend(request):
    """Run the test once per target. Native backends are always started with gdb, then migrated."""
    return request.param


@pytest.fixture
def known_gaps(request):
    """
    known_gaps(backend, {"new_libdebug": "why"}) marks the current run as an expected failure.
    Keys can be groups ("qemu", "foreign"...). Strict: when the gap is closed the test reports XPASS(strict)
    and the entry must be removed. Prefer the known_gap marker: it doesn't even start the debugger.
    """
    def mark(current, gaps):
        for spec, reason in gaps.items():
            if current in expand(spec):
                request.applymarker(pytest.mark.xfail(strict=True, reason=f"{current}: {reason}"))
                return
    return mark


@pytest.fixture
def not_applicable():
    """
    not_applicable(backend, {"libdebug": "why"}) skips the current run as "not applicable" in the dashboard:
    the feature can't exist on that backend by design (unlike known_gaps, nothing has to be fixed).
    Prefer the not_applicable marker: it skips before the debugger is started.
    """
    def skip(current, domains):
        for spec, reason in domains.items():
            if current in expand(spec):
                pytest.skip(f"not applicable: {reason}")
    return skip


@pytest.fixture
def target_binary(request, fixture_binary, tmp_path):
    """
    target_binary("basic") -> the fixture built for the current target: basic, basic_i386, basic_arm..., or for
    aarch64_remote a copy of the one built on the machine of --remote-gdbserver.
    Tests that don't run over the target axis get the x86-64 one.
    """
    backend = request.getfixturevalue("backend") if "backend" in request.fixturenames else "gdb"

    def get(name):
        if backend == "aarch64_remote":
            try:
                return request.getfixturevalue("remote_host").binary(name, tmp_path)
            except RuntimeError as error:
                pytest.skip(f"could not build fixture {name} on the arm64 machine: {error}")
        if backend == "i386" or backend in QEMU_ARCHES:
            return fixture_binary(f"{name}_{backend}")
        return fixture_binary(name)
    return get


@pytest.fixture
def basic(target_binary):
    return target_binary("basic")


@pytest.fixture
def sysno():
    """sysno("getpid") -> number of the syscall for the binary being debugged (pwntools lacks mips64 and riscv32)"""
    from pwn import constants, context
    generic = {"read": 63, "write": 64, "getpid": 172, "getppid": 173, "close": 57, "openat": 56, "mprotect": 226}
    missing = {"riscv32": generic, "riscv64": generic,
               "mips64": {"read": 5000, "write": 5001, "getpid": 5038, "getppid": 5108, "close": 5003, "openat": 5247, "mprotect": 5010}}

    def get(name):
        table = missing.get(context.arch)
        if table is not None and name in table:
            return table[name]
        return int(getattr(constants, f"SYS_{name}"))
    return get


@pytest.fixture
def run_without_debugger():
    """Oracle: what the program prints when nobody debugs it."""
    def run(argv, stdin=b""):
        return subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30).stdout
    return run
