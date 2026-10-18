from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable
    from gdb_plus.gdb_plus import Debugger
    # gdb: rpyc netref of gdb.Breakpoint (pwntools' .server_breakpoint), legacy libdebug: the address, new libdebug: its Breakpoint
    from gdb import Breakpoint as NativeGdbBreakpoint
    from libdebug.data.breakpoint import Breakpoint as LibdebugBreakpoint

@dataclass
class Inner_Breakpoint:
    byte: bytes | None = None
    temporary: bool = False

# I need a way to no if the process stopped due to my debugger or an action done manually
class Breakpoint:
    def __init__(self, breakpoint: NativeGdbBreakpoint | int | LibdebugBreakpoint, address: int, callback: Callable[[Debugger], bool | int | None] | None = None, temporary: bool = False, user_defined: bool = True, hw: bool = False) -> None:
        self.native_breakpoint = breakpoint
        self.address = address
        self.callback = callback
        self.temporary = temporary
        self.user_defined = user_defined
        self.hw = hw
