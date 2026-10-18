"""
What the machine running the tests can do. Every check is cached because some are slow (sage).
"""
import fcntl
import functools
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
FIXTURES = TESTS / "fixtures"

QEMU_BINARIES = {
    "i386": "qemu-i386",
    "arm": "qemu-arm",
    "aarch64": "qemu-aarch64",
    "riscv32": "qemu-riscv32",
    "riscv64": "qemu-riscv64",
    "mips": "qemu-mips",
    "mips64": "qemu-mips64",
}

GEF_CANDIDATES = ["~/.gdbinit-gef.py", "~/gef/gef.py", "~/.gef/gef.py", "/root/.gdbinit-gef.py"]
PWNDBG_CANDIDATES = ["~/pwndbg/gdbinit.py", "~/Tools/pwndbg/gdbinit.py", "/home/root/pwndbg/gdbinit.py", "~/.pwndbg/gdbinit.py"]


@functools.lru_cache(None)
def has_gdb() -> bool:
    return shutil.which("gdb") is not None and shutil.which("gdbserver") is not None


@functools.lru_cache(None)
def has_qemu(arch: str) -> bool:
    return shutil.which("gdb-multiarch") is not None and shutil.which(QEMU_BINARIES[arch]) is not None


@functools.lru_cache(None)
def qemu_catches_syscalls(arch: str) -> bool:
    """Does qemu-user's gdbstub report syscalls to gdb (catch syscall)? Old versions answer that it doesn't."""
    binary = FIXTURES / "bin" / f"basic_{arch}"
    if not has_qemu(arch) or not binary.exists():
        return False
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    emulator = subprocess.Popen([QEMU_BINARIES[arch], "-g", str(port), str(binary)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        output = subprocess.run(["gdb-multiarch", "-nx", "-batch", "-ex", f"file {binary}",
                                 "-ex", f"target remote 127.0.0.1:{port}", "-ex", "catch syscall write",
                                 "-ex", "continue"], capture_output=True, text=True, timeout=30).stdout
    except subprocess.TimeoutExpired:
        return False
    finally:
        emulator.kill()
        emulator.wait()
    return "Catchpoint 1 (call to syscall" in output or "Catchpoint 1 (returned from syscall" in output


@functools.lru_cache(None)
def has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def has_legacy_libdebug() -> bool:
    return has_module("libdebug_legacy")


@functools.lru_cache(None)
def has_new_libdebug() -> bool:
    if not has_module("libdebug"):
        return False
    try:
        from importlib.metadata import version
        major, minor = (int(x) for x in version("libdebug").split(".")[:2])
        return (major, minor) >= (0, 8)
    except Exception:
        return False


def has_sage() -> bool:
    return has_module("sage")


@functools.lru_cache(None)
def has_libclang() -> bool:
    try:
        from gdb_plus.extra.setup_clang import get_clang_lib_path
        get_clang_lib_path()
        return True
    except Exception:
        return False


def _first_existing(env_variable, candidates):
    if os.environ.get(env_variable):
        path = Path(os.environ[env_variable]).expanduser()
        return path if path.exists() else None
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.exists():
            return path
    return None


@functools.lru_cache(None)
def gef_path():
    """GEF's gef.py. Override with GDB_PLUS_GEF=/path/to/gef.py"""
    return _first_existing("GDB_PLUS_GEF", GEF_CANDIDATES)


@functools.lru_cache(None)
def pwndbg_path():
    """pwndbg's gdbinit.py. Override with GDB_PLUS_PWNDBG=/path/to/gdbinit.py"""
    return _first_existing("GDB_PLUS_PWNDBG", PWNDBG_CANDIDATES)


@functools.lru_cache(None)
def build_fixtures() -> set:
    """Compile tests/fixtures. Return the names of the binaries that exist afterwards."""
    if shutil.which(os.environ.get("CC", "gcc")) is not None and shutil.which("make") is not None:
        # The workers of pytest -n all build at startup: one at a time, the others then find everything up to date
        with open(FIXTURES / ".build.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            # i386 needs gcc-multilib and cross needs clang + lld: build them separately and ignore their failure
            for target in ["native", "i386", "cross"]:
                subprocess.run(["make", "-s", "-C", str(FIXTURES), target],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    binaries = FIXTURES / "bin"
    return {path.name for path in binaries.iterdir()} if binaries.exists() else set()


def ld_prefix_for(arch: str):
    """Sysroot to run dynamically linked foreign binaries (same lookup as pwntools)."""
    from pwnlib import qemu
    from pwn import context
    with context.local(arch=arch):
        return qemu.ld_prefix()
