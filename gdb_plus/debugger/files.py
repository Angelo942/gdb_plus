from __future__ import annotations

from pathlib import Path

from pwn import context, log

from gdb_plus.utils import DEBUG, EXE
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF

class FilesMixin(DebuggerBase):
    """
    The files of the process and their addresses, as the user sees them: exe, the libraries, symbols, maps, libs and
    the base addresses. The work is done by the address space, self.space (AddressSpace). This mixin keeps what reads
    the process itself: the raw maps (_raw_maps) and the download of the files of a remote gdbserver.
    """
    @property
    def _exe(self) -> EXE | None:
        """The executable, without placing it in memory first (see exe). Stored in the address space"""
        return self.space._exe
    @_exe.setter
    def _exe(self, exe: EXE | None) -> None:
        self.space._exe = exe
    def local_path(self, path: str | Path) -> Path | None:
        """The path of the local copy of `path`, a file of the local machine or of the remote server (AddressSpace.local_path)"""
        return self.space.local_path(path)
    def remote_path(self, path: str | Path) -> Path:
        """The absolute path of `path` on the remote server (AddressSpace.remote_path)"""
        return self.space.remote_path(path)
    @property
    def maps(self) -> dict[int, int]:
        """Start address -> size of every mapping of the debugged program."""
        return self.space.maps
    @property
    def libs(self) -> dict[str, list[int]]:
        """Path of each file mapped by the process -> [first address, last address] (AddressSpace.libs)"""
        return self.space.libs
    def access_library(self, name: str | Path, local_path: str | Path | None = None) -> EXE | None:
        """The EXE of the library `name`, placed at its address in the process (AddressSpace.access_library)"""
        return self.space.access_library(name, local_path)
    @property
    def libraries(self) -> dict[str, EXE | None]:
        """Name -> EXE of every library the executable needs, loaded on first access (AddressSpace.libraries)"""
        return self.space.libraries
    @property
    def ld(self) -> EXE | None:
        """The loader of the process, None if there is none (AddressSpace.ld)"""
        return self.space.ld
    @ld.setter
    def ld(self, elf_ld: EXE) -> None:
        self.space.ld = elf_ld
    @property
    def exe(self) -> EXE | None:
        """The executable, placed at its address in the process (AddressSpace.exe)"""
        return self.space.exe
    elf = exe
    @property
    def symbols(self) -> dict[str, int]:
        """Name -> address of the symbols of the executable and of every library, without the PLT and GOT entries (AddressSpace.symbols)"""
        return self.space.symbols

    def download(self, source: str | Path, destination: str | Path) -> None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return
        assert not self.local_debugging, "why are you trying to download files that are already on your system ?"
        assert self.gdb is not None
        if self.gdbserver_qemu is not None:
            stopped = self.gdbserver_qemu.interrupt()
            self.gdbserver_qemu.download(source, destination)
            if stopped:
                self.gdbserver_qemu.c(wait=False)
        else:
            try:
                self.execute(f"remote get {source} {destination}")
            except Exception as e:
                if not context.native and self.pid is None:
                    log.error("Can not download files from qemu's gdbstup. Please debug qemu itself and pass it in Debugger(..., qemu_gdbserver=...)")
                else:
                    if DEBUG: self.logger.warning("Could not download %s", source)

    # We may want to cache it in gdbserver_qemu
    def _raw_maps(self) -> str:
        if not self.debugging:
            return ""

        if self.local_debugging:
            with open(f"/proc/{self.pid}/maps") as fd:
                maps_raw = fd.read()
        elif self.pid is not None:
            maps_raw = self.execute("info proc map")
        elif self.gdbserver_qemu is not None:
            was_running = self.gdbserver_qemu.interrupt()
            maps_raw = self.gdbserver_qemu.execute("info proc map")
            if was_running:
                self.gdbserver_qemu.c(wait=False)
        else:
            # I assume that the user has already been warned when initializing the debugger [07/05/25]
            # log.warn_once("can not access maps under QEMU.")
            return ""
        return maps_raw

    # NOTE: Here for backward compatibility with 7.0 
    @property
    def base_libc(self) -> int:
        if self.libc is None:
            log.error("I don't see a libc ! Set dbg.libc = ELF(<path_to_libc>)")
        return self.libc.address

    @base_libc.setter
    def base_libc(self, address: int) -> None:
        if self.libc is None:
            log.error("I don't see a libc ! Set dbg.libc = ELF(<path_to_libc>)")
        self.libc.address = address

    libc_address = base_libc

    # NOTE: Here for backward compatibility with 7.0 
    @property
    def base_elf(self) -> int:
        return self._exe.address

    @base_elf.setter
    def base_elf(self, address: int) -> None:
        self._exe.address = address

    elf_address = base_elf

    exe_address = base_elf


