"""Which executable a Debugger(target, binary=...) describes, and the logging helpers."""
import logging
import shutil

import pytest
from pwn import ELF

from gdb_plus.setup import identify_executable
from gdb_plus.utils import logger
from gdb_plus.utils.exe import EXE

BINARY = shutil.which("true")


@pytest.mark.parametrize("kind", ["str", "ELF", "EXE"])
def test_binary_wins_over_the_target(kind):
    """
    identify_executable(): binary= decides the executable whatever the target is; an EXE passed in is used as is, not
    reloaded.
    """
    binary = {"str": BINARY, "ELF": ELF(BINARY, checksec=False), "EXE": EXE(BINARY, checksec=False)}[kind]
    exe = identify_executable(1234, binary)
    assert isinstance(exe, EXE) and exe.path == BINARY
    if kind == "EXE":
        assert exe is binary  # not reloaded


@pytest.mark.parametrize("kind", ["str", "ELF", "EXE"])
def test_target_is_the_binary(kind):
    """Without binary=, a path, ELF or EXE target is the executable."""
    target = {"str": BINARY, "ELF": ELF(BINARY, checksec=False), "EXE": EXE(BINARY, checksec=False)}[kind]
    exe = identify_executable(target, None)
    assert isinstance(exe, EXE) and exe.path == BINARY


@pytest.mark.parametrize("target", [1234, [BINARY, "--help"], ("127.0.0.1", 1234)], ids=["pid", "argv", "gdbserver"])
def test_targets_without_a_binary(target):
    """A pid, an argv list or a (host, port) target gives no executable yet: it is found later or given with binary=."""
    # A pid, an argv or a gdbserver: the executable is found later (info proc) or given with binary=
    assert identify_executable(target, None) is None


def test_unknown_types_are_rejected():
    """identify_executable() raises TypeError for a target or binary of an unknown type."""
    with pytest.raises(TypeError):
        identify_executable(3.14, None)
    with pytest.raises(TypeError):
        identify_executable(BINARY, 3.14)


def test_unexpected_warns_users(monkeypatch):
    """unexpected() warns once and asks to raise an issue when strict mode is off."""
    warnings = []

    class Log:
        def warn_once(self, message):
            warnings.append(message)
    monkeypatch.setattr(logger, "STRICT", False)
    logger.unexpected("this should not happen.", Log())
    assert warnings == ["this should not happen. Please raise an issue."]


def test_unexpected_crashes_in_strict_mode(monkeypatch):
    """In strict mode (GDB_PLUS_STRICT=1) unexpected() raises instead of warning."""
    monkeypatch.setattr(logger, "STRICT", True)
    with pytest.raises(RuntimeError, match="this should not happen"):
        logger.unexpected("this should not happen.", None)


@pytest.mark.parametrize("level, color", [(logging.DEBUG, "\033[37m"), (logging.WARNING, "\033[33m"), (logging.CRITICAL, "\033[1;31m")])
def test_log_levels_have_colors(level, color):
    """The log formatter colours each level (debug grey, warning yellow, critical bold red)."""
    record = logging.LogRecord("gdb_plus", level, __file__, 1, "message", None, None)
    assert logger.LevelColorFormatter("%(message)s").format(record) == f"{color}message\033[0m"
