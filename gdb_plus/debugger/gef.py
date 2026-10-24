from __future__ import annotations

from pwn import log

from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF

class GefMixin(DebuggerBase):
    """
    Shortcuts to the commands of GEF and pwndbg: context, bins, chunks, telescope.
    """
    def context(self) -> None:
        """
        print memory infos as in gdb
        """
        print(self.execute("context"))

    #Works only with GEF. I use them to avoid writing down print(self.execute("heap bins")) every time
    def bins(self) -> None:
        stopped = self.interrupt()
        if self._gef:
            print(self.execute("heap bins"))
        elif self._pwndbg:
            print(self.execute("bins"))
        else:
            print("GEF or pwndbg not detected")
        if stopped:
            self.c(wait=False)

    def chunks(self) -> None:
        stopped = self.interrupt()
        if self._gef:
            print(self.execute("heap chunks"))
        elif self._pwndbg:
            print(self.execute("heap"))
        else:
            print("GEF or pwndbg not detected")
        if stopped:
            self.c(wait=False)

    def telescope(self, address: int | None = None, length: int = 10, reference: int | None = None) -> None:
        """
        reference: int -> print the offset of each pointer from the reference pointer 
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if self._gef:
            print(self.execute(f"telescope {hex(address) if address is not None else ''} -l {length} {'-r ' + hex(reference) if reference is not None else ''}"))
        elif self._pwndbg:
            print(self.execute(f"telescope {hex(address) if address is not None else ''} {length}"))
        else:
            print("telescope requires GEF or pwndbg")
