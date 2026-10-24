"""
Keeps `gdb_plus.gdb_plus` importable with its public names: Debugger and the constants of gdb_plus/debugger/, plus the
pwntools and gdb_plus.utils names it re-exports. No code lives here.
gdb_plus/__init__.py does `from gdb_plus.gdb_plus import *`: a name removed here also disappears from
`from gdb_plus import *`.
"""
from __future__ import annotations

import os
import sys
import signal
import logging
import weakref
from pathlib import Path
from functools import partial
from collections import defaultdict
from math import ceil, inf
from queue import Queue
from threading import Event, enumerate as enumerate_threads
from multiprocessing import Process, Event as p_Event, Queue as p_Queue, cpu_count
from typing import TYPE_CHECKING

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_RISCV, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
# Migrate to capstone v6, but keep support for v5
try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64
    CS_ARCH_AARCH64 = CS_ARCH_ARM64
from elftools.elf.sections import SymbolTableSection
from pwn import ELF, args, constants, context, gdb, log, p32, pack, process, remote, sleep, unpack
from pwnlib.elf.datatypes import AT_CONSTANTS
from pwnlib.exception import PwnlibException
from rpyc import BgServingThread

from gdb_plus.utils import *
from gdb_plus.utils.exe import EXE
from gdb_plus.setup import identify_executable

from gdb_plus.debugger._base import (
    _logger, ch, formatter, DEBUG_OFF, IMPORTANT_DEBUG_OFF, SHOULD_STOP, SKIP_SYSCALL, INTERRUPT_SENT, INTERRUPT_HIT_BREAKPOINT,
    _RESTART_SYSCALL, _NEW_LIBDEBUG_REGISTERS, lock_decorator, context_decorator, GdbDiedError, _kill_gdb,
)
from gdb_plus.debugger import Debugger
