from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

from gdb_plus.utils import DEBUG, Breakpoint
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF

if TYPE_CHECKING:
    from collections import defaultdict
    from typing import Callable
    from gdb_plus.debugger.debugger import Debugger

class BreakpointsMixin(DebuggerBase):
    """
    Breakpoints (b, tb, delete_breakpoint) and the addresses they accept: _parse_address() turns a symbol,
    "symbol+offset" or a PIE-relative int into an absolute address, reverse_lookup() does the opposite.
    """

    @property
    def breakpoints(self) -> defaultdict[int, list[Breakpoint]]:
        """Address -> the Breakpoints set there, the temporary ones included (kept by the Controller)"""
        return self.control.breakpoints
    def _parse_address(self, location: int | str) -> int:
        """The absolute address of a symbol, "symbol+offset" or PIE-relative int (AddressSpace.parse_address)"""
        return self.space.parse_address(location)
    def reverse_lookup(self, address: int | str) -> str:
        """"symbol(address)" when a symbol starts at `address`, otherwise its hex (AddressSpace.reverse_lookup)"""
        return self.space.reverse_lookup(address)
    # May want to put breakpoints relative to the libc too?
    # I want to keep legacy breakpoints for the ones I set with the library because we must be able to work manually when emulating ptrace [23/03/23]
    # legacy_callback will be deprecated once I can overwrite gdb's nexti to keep his breakpoint even if the process gets interrupted [27/04/23]
    def b(self, location: int | str, callback: Callable[[Debugger], bool | int | None] | None = None, legacy_callback: Callable[[Debugger], bool | int | None] | None = None, temporary: bool = False, user_defined: bool = True, hw: bool = False) -> Breakpoint | None:
        """
        Set a breakpoint in your process.

        Parameters
        ----------
        address : int or str
            If address is and integer smaller than 0x10000 the address will be interpreted as a relative address
            Breakpoints are accessible from self.breakpoints as a dictionary where the key is hex(address) or the name of the function
        callback : FUNCTION, optional
            Pass a function to execute when the breakpoint is reached.
            callback takes a pointer to the debugger as parameter and should return True if you want to interrupt the execution and False otherwise. If you forget a return value the default behaviour is to interrupt the process when reaching the breakpoint
            You can use Queue to pass data between your exploit and the callbacks
        temporary : BOOL, optional
            Don't save the breakpoint and disable it when hit
        user_defined : BOOL, restricted
            Flag to identify breakpoints set by the library from the ones used by the users. Don't touch it.

        Returns
        -------
        Breakpoint
            Return a pointer to the breakpoint set
            I don't see when you would need it, but here it is
        """

        # Move from callback to real_callback
        # real_callbacks have problems, but with features not even available with simple callbacks. Furthermore now you can use return False with temporary breakpoints
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if legacy_callback is not None:
            log.warn_once("legacy_callback is deprecated. Please use normal callback or raise an issue if something specific is not possible with them.")

        address = self._parse_address(location)


        if hw:
            if DEBUG: self.logger.debug("putting hardware breakpoint in %s", self.reverse_lookup(address))
        else:
            if DEBUG: self.logger.debug("putting breakpoint in %s", self.reverse_lookup(address))
        
        breakpoint = self._backend.breakpoint(address, legacy_callback, callback, temporary, user_defined, hw)

        self.control.breakpoints[address].append(breakpoint)
        return breakpoint

    breakpoint = b

    def tb(self, location: int | str, callback: Callable[[Debugger], bool | int | None] | None = None, legacy_callback: Callable[[Debugger], bool | int | None] | None = None, user_defined: bool = True, hw: bool = False) -> Breakpoint | None:
        return self.b(location, callback, legacy_callback, temporary=True, user_defined=user_defined, hw=hw)

    temporary_breakpoint = tb

    def delete_breakpoint(self, breakpoint: int | str | Breakpoint) -> None:
        """
        Delete a particular breakpoint
        If an address (or symbol) is passed the only user defined at that address will be deleted
        
        If possible pass the breakpoint itself
        """

        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if type(breakpoint) is not Breakpoint:
            location = breakpoint
            address = self._parse_address(location)
            # Is there a case where it isn't ?? [17/04/23]
            user_breakpoints = [b for b in self.control.breakpoints[address] if b.user_defined]
            if len(user_breakpoints) == 0:
                raise Exception(f"No breakpoint at address {hex(address)}")
            if len(user_breakpoints) > 1:
                raise Exception(f"You set multiple breakpoint at {hex(address)}! Which one should I delete ???")
            breakpoint = user_breakpoints[0]

        self.control.breakpoints[breakpoint.address].pop(self.control.breakpoints[breakpoint.address].index(breakpoint))
        self._backend.delete_breakpoint(breakpoint)
