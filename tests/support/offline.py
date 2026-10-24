"""
A Debugger that never starts gdb: registers are plain attributes and memory is a dict of
regions. It lets the unit tests exercise the pure logic of the Debugger (typed memory helpers,
address parsing, symbol merging, maps parsing, backups, argument lookup...) in milliseconds.

How it works: Debugger.__setattr__ only forwards registers to a backend once `_initialized` is
True, and context_decorator only applies the saved context once `_initialized` is True. We never
set it, so every register assignment lands in __dict__ and the caller's `context` is used.
"""
from threading import Event

from pwn import context

from gdb_plus import Debugger
from gdb_plus.debugger import PtraceEmulator
from gdb_plus.debugger.engines import Backend
from gdb_plus.debugger.space import AddressSpace
from gdb_plus.debugger.control import Controller

# The attributes the tests pass under the name the Debugger had for them -> their name in the Controller
CONTROL = {"_event_table": "event_table", "_event_breakpoints": "event_breakpoints", "_handled_signals": "handled_signals",
           "_closed": "closed", "_out_of_breakpoint": "out_of_breakpoint", "breakpoints": "breakpoints"}


class FakeMemory:
    """Sparse memory made of mapped regions. Reading or writing outside them raises like gdb."""

    def __init__(self):
        self.regions = {}  # start -> bytearray

    def map(self, start: int, data: bytes = b"", size: int = None):
        size = len(data) if size is None else size
        region = bytearray(size)
        region[:len(data)] = data
        self.regions[start] = region
        return start

    def _locate(self, address, size):
        for start, region in self.regions.items():
            if start <= address and address + size <= start + len(region):
                return region, address - start
        raise MemoryError(f"Cannot access memory at address {address:#x}")

    def read(self, address, size):
        region, offset = self._locate(address, size)
        return bytes(region[offset:offset + size])

    def write(self, address, data):
        region, offset = self._locate(address, len(data))
        region[offset:offset + len(data)] = data


class FakeExe:
    """The few attributes of EXE that the offline paths look at."""

    def __init__(self, *, pie=False, address=0, end_address=None, symbols=None, plt=None, got=None,
                 bss=0x404000, statically_linked=True, name="fake"):
        self.pie = pie
        self.address = address
        self.end_address = end_address
        self.symbols = dict(symbols or {})
        self.plt = dict(plt or {})
        self.got = dict(got or {})
        self._bss = bss
        self.statically_linked = statically_linked
        self.name = name

    def bss(self):
        return self._bss

    @property
    def range(self):
        return 0 if self.end_address is None else self.end_address - self.address

    size = range

    def __contains__(self, value):
        return self.end_address is not None and self.address < value < self.end_address


class OfflineDebugger(Debugger):
    def read(self, address, size, *, inferior=None, pid=None):
        return self.memory.read(address, size)

    def write(self, address, data, *, inferior=None, pid=None, heap=True):
        if address is None:
            address = self.alloc(len(data), heap=heap)
        self.memory.write(address, data)
        return address

    def execute(self, code):
        self.executed.append(code)
        return self.execute_results.get(code, "")

    # What /proc/pid/maps (or `info proc map`) would contain
    def _raw_maps(self):
        return self.raw_maps


def offline_debugger(*, exe=None, registers=None, memory=None, libraries=None, raw_maps="", **attributes):
    """
    Build an OfflineDebugger for the current context.arch.
    All registers of the architecture start at 0 unless given in `registers`.
    """
    dbg = Debugger.__new__(OfflineDebugger)
    state = dict(
        debugging=True, local_debugging=True, p=None, pid=4242,
        _context_params=context.copy(), _backends={}, _args=None, _sys_args=None, _free_bss=None,
        _canary=None, _saved_auxiliary_vector=None, _capstone=None, children={},
        memory=memory if memory is not None else FakeMemory(), executed=[], execute_results={},
        raw_maps=raw_maps, gdbserver_qemu=None,
    )
    # The state of the address space (dbg.space) and the engine handles (properties stored in the backends) are set apart
    space = dict(_exe=exe if exe is not None else FakeExe(), _libraries=dict(libraries or {}), _symbols=None, _ld=None,
                 download_libraries=False, _qemu_guest_base=0)
    space.update({name: attributes.pop(name) for name in list(space) if name in attributes})
    control = dict(breakpoints={}, handled_signals={}, closed=Event())
    control.update({new: attributes.pop(old) for old, new in CONTROL.items() if old in attributes})
    engines = {name: attributes.pop(name) for name in ("gdb", "libdebug", "new_libdebug") if name in attributes}
    state.update(attributes)
    dbg.__dict__.update(state)
    dbg.__dict__.setdefault("ptrace", PtraceEmulator(dbg))
    dbg.__dict__["_backend"] = dbg._backend_of(Backend)
    dbg.__dict__["space"] = AddressSpace(dbg, download=False)
    dbg.__dict__["control"] = Controller(dbg)
    dbg.control.__dict__.update(control)
    dbg.space.__dict__.update(space)
    for name, handle in engines.items():
        setattr(dbg, name, handle)
    for register in dbg._special_registers + dbg._registers:
        dbg.__dict__[register] = 0
    dbg.__dict__.update(registers or {})
    return dbg
