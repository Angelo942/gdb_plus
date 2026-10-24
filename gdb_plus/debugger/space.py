from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from pwn import context, log

from gdb_plus.utils import DEBUG, unexpected, EXE
from gdb_plus.debugger._base import context_decorator

if TYPE_CHECKING:
    from typing import Any
    from gdb_plus.debugger.debugger import Debugger

class AddressSpace:
    """
    The files mapped in the process and where they are: the executable and the libraries (EXE objects that know their
    base address), the symbols of all of them, the memory map (with the guest base under qemu-user), the local copies
    of the files of a remote gdbserver, and the addresses the user writes ("main+0x12", PIE-relative ints).
    dbg.space, created by DebuggerBase._init_state(); the Debugger exposes it through its public names (dbg.exe,
    dbg.libs, dbg.symbols...).
    It owns its state. What it needs to know about the process comes from its Debugger, self.dbg: whether and where the
    process is debugged (debugging, local_debugging, pid, gdb), the raw maps (_raw_maps), gdb commands (execute), the
    download of remote files (download), its logger and the libc (dbg.libc).
    Its methods run on the thread of the Debugger method that calls them, without a lock of their own.
    """
    def __init__(self, dbg: Debugger, *, download: bool) -> None:
        self.dbg = dbg
        self._exe: EXE | None = None # self._exe can be None if binary is None and the target is a remote process from which we can't download the binary. Should never happen though
        self._ld: EXE | int | None = None # -1 once we know there is none
        self._symbols: dict[str, int] | None = None
        self._libraries: dict[str, EXE | None] = {}
        self._qemu_guest_base: int | None = None # See find_qemu_guest_base
        self.download_libraries = download
    # context_decorator reads these on the object whose method it decorates
    @property
    def _initialized(self) -> bool:
        return self.dbg._initialized
    @property
    def _context_params(self) -> dict[str, Any]:
        return self.dbg._context_params
    # Should we check that we are debugging remotely ? [19/10/26]
    def local_path(self, path: str | Path) -> Path | None:
        """
        Given a path that can be on the remote server or the local machine returns the path to the local copy of that file. 
        DONT USE if you are sure the path given is already the one of a local copy of the binary.
        """
        dbg = self.dbg
        if DEBUG: dbg.logger.debug(f"searching for {path}")
        path = Path(path)
        gdb_files_path = Path("./gdb_files")
        gdb_file_path = gdb_files_path / path.name
        gdb_file_path_exists = gdb_file_path.is_file() and gdb_file_path.exists()

        # By default if we have a gdb_files directory we assume that the libraries are here
        # This avoids problems when pwning the remote server 
        if gdb_file_path_exists:
            return gdb_file_path

        if not dbg.debugging:
            return path if path.exists() else None

        if dbg.local_debugging and path.exists():
            return path

        # This is only when debugging a remote gdbserver

        if self.download_libraries:
            remote_path = self.remote_path(path)
            gdb_files_path.mkdir(exist_ok=True)
            dbg.download(remote_path, gdb_file_path)
            return gdb_file_path
        else:
            if path.exists():
                log.warn_once("The library %s used may not be the exact same as the one on the remote server. If you want to download the one on the server set Debugger(..., download=True)", path)
                return path
            elif Path(path.name).exists():
                # We allow the case where the executable is in the same directory as the solve script. Although it may not be clean it's easier for the user. I just hope to not hide too much a problem.
                return Path(path.name)
            else:
                log.warn_once("Can not find %s. Please set Debugger(..., download=True) if you want to copy if from the remote server.", path)
                return None
    # TODO handle symlinks. We may have a path to a symlink while in the maps the real file is present.
    # Should this be accessible if we are not debugging anything ? [18/10/26]
    def remote_path(self, path: str | Path) -> Path:
        """
        Find absolute path on the remote server.
        """
        dbg = self.dbg
        if DEBUG: dbg.logger.debug(f"searching for {path} on remote server")
        path = Path(path)
        for lib in self.libs:
            if path.name in lib:
                return Path(lib)
        unexpected(f"can not find path {path}", log)
    def parse_maps(self, maps_raw: str) -> list[tuple[int, int, str | None]]:
        """
        (start, end, path) of every mapping listed by /proc/pid/maps or `info proc map`, path None for anonymous ones.
        Under QEMU the list stops at the qemu binary: what follows are the emulator's own libraries.
        """
        entries = []
        for line in maps_raw.splitlines():
            path = line[line.index('/'):].strip() if '/' in line else None # gdb 17 pads the File column of info proc map with a trailing space
            if not context.native and path is not None and "/qemu-" in path:
                if "-static" in path: # Qemu static can be located at the top of our memory, so we shouldn't stop. Since it  doesn't import libraries it is not a problem for us to read all maps [19/05/25]
                    continue
                else:
                    break
            # /proc/pid/maps uses "start-end", while info proc map uses "start    end"
            parts = line.replace("-", " ").split()
            try:
                entries.append((int(parts[0], 16), int(parts[1], 16), path))
            except (IndexError, ValueError): # Headers of info proc map
                continue
        return entries
    def find_qemu_guest_base(self, entries: list[tuple[int, int, str | None]]) -> int:
        """
        Offset qemu-user adds to every guest address to place it in its own memory (guest_base): 0 for 64-bit guests,
        usually vm.mmap_min_addr for 32-bit ones, whose whole 4 GB space qemu reserves starting from guest address 0.
        Found by comparing where the host maps (`entries`, untranslated) place the executable with the guest address of
        its program headers in the auxiliary vector (AT_PHDR). Cached, since qemu chooses it once for its lifetime.
        Returns 0 with a warning when it can't be found.
        """
        dbg = self.dbg
        if self._qemu_guest_base is not None:
            return self._qemu_guest_base
        exe = self._exe
        host_start = phdr = segment = None
        if exe is not None:
            host_start = next((start for start, _, path in entries if path is not None and Path(path).name == exe.name), None)
            try:
                auxv = dbg.execute("info auxv")
            except Exception:
                auxv = ""
            for line in auxv.splitlines():
                parts = line.split()
                if len(parts) > 2 and parts[1] == "AT_PHDR":
                    phdr = int(parts[-1], 16)
            loads = [seg.header for seg in exe.iter_segments_by_type("PT_LOAD")]
            phoff = exe.header.e_phoff
            segment = next((h for h in loads if h.p_offset <= phoff < h.p_offset + h.p_filesz), None)
        if host_start is None or phdr is None or segment is None:
            log.warn_once("can not find where QEMU places the guest memory: maps and libs may use host addresses")
            return 0
        # The program headers are loaded with the segment that contains them: this gives the load bias of a PIE (0 otherwise)
        load_bias = phdr - (segment.p_vaddr + phoff - segment.p_offset)
        guest_start = load_bias + (min(h.p_vaddr for h in loads) & ~0xfff)
        self._qemu_guest_base = host_start - guest_start
        return self._qemu_guest_base
    def entries(self) -> list[tuple[int, int, str | None]]:
        """
        (start, end, path) of every mapping of the debugged program, in the program's own address space.
        Under qemu-user the maps come from the emulator process, in host addresses: they are translated to guest
        addresses and the mappings outside the guest address space are dropped.
        """
        dbg = self.dbg
        entries = self.parse_maps(dbg._raw_maps())
        # Only a remote gdbserver with a known pid lists the guest maps itself
        if context.native or context.os == "baremetal" or not (dbg.local_debugging or dbg.pid is None) or not entries:
            return entries
        guest_base = self.find_qemu_guest_base(entries)
        guest_size = 1 << context.bits
        return [(start - guest_base, end - guest_base, path) for start, end, path in entries if guest_base <= start and end - guest_base <= guest_size]
    @property
    @context_decorator
    def maps(self) -> dict[int, int]:
        """Start address -> size of every mapping of the debugged program."""
        return {start: end - start for start, end, _ in self.entries()}
    # I copied it from pwntools to have access to it even if I attach directly to a pid 
    # We still need pwntools when we are not debugging the process. It is needed for example to access the libc while pwning a remote challenge. 
    # I assume that you don't care about the address when you are not debugging the program
    # The main advantage now though is just the speed of not having to run a new process every time we call the function if we are already debugging it.
    # If we are working under QEMU and not debugging the process pwntools implementations of elf.libs may fail. If you see this problem we will need to run a debugger ourselves.
    # The idea of using fake_terminal.py is terrible. Somehow it is 3 times slower, so it's not worth it just to prevent having a terminal popping up.
    @property
    @context_decorator
    def libs(self) -> dict[str, list[int]]:
        """
        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """
        if not self.dbg.debugging:
            # We can do this if we really need it [09/05/25]
            # Opening a debugger is not great, but it should happen only if you try to access the libc while pwning remotely a challenge on a foreign architecture. Not often, but we can first try to access downloaded files.
            if context.native:
                maps = self._exe.libs
                for key in maps:
                    maps[key] = [maps[key], maps[key]]
                return maps
            elif self._exe is not None:
                from gdb_plus.debugger.debugger import Debugger # not at the top: debugger.py imports this module
                with Debugger(self._exe, aslr=False, from_entry=True) as dbg:
                        return dbg.libs
            else:
                return {}
        # Enumerate all of the libraries actually loaded right now: [first start, last end] of the pages of each file
        maps = {}
        for start, end, path in self.entries():
            if path is None:
                continue
            if path not in maps:
                maps[path] = [start, end]
            maps[path][-1] = end
        return maps
    @context_decorator
    def set_range(self, file: EXE) -> None:
        """
        Set the base address of `file` to the first page the program maps from it. The end of the range comes from the
        program headers (EXE.end_address), so it includes the .bss that the maps list without a path.
        """
        dbg = self.dbg
        if not dbg.debugging:
            return
        for path, addresses in self.libs.items():
            if file.name == Path(path).name:
                file.address = addresses[0]
                return
        log.warn(f"can not find {file.name} in the binaries loaded in gdb")
    # How does this interact with remote debugging ? [26/03/25]
    # Let's introduce local_path hoping it's enough and call it a day for now. [26/03/25]
    # We can not expect the user to load manually the libc, but must make it accessible when using REMOTE, so we have to find it by debugging the program anyway. [13/04/25]
    # It would be nice to find the path to the library without having to debug the program. [13/04/25]
    def access_library(self, name: str | Path, local_path: str | Path | None = None) -> EXE | None:
        """
        Create the EXE object for a particular library. The entry will always be with the name of the library, but if you pass a full path we can find it faster.
        The path can be the path on the remote server.
        """
        if self._libraries.get(name, None) is not None:
            log.info(f"{name} is already accessible as dbg.{name}")
            return self._libraries[name]

        if local_path is not None:
            path = local_path

        # If we already downloaded the library look for it. (Maybe we have to worry about name collisions but it's so rare it's not gonna come up in the next few years) [09/05/25] 
        elif (path := self.local_path(name)) is not None:
                print(f"found {path}")

        else:
            found_path = None
            for path in self.libs:
                library_name = Path(path).name
                if str(name) in library_name:
                    if found_path is not None:
                        log.warn(f"Name is not specific enough! Could mean both {found_path} and {path}")
                    found_path = path
            if found_path is None:
                msg = "\n".join([
                    f"{name} cannot be found between:",
                    *[f" - {path}" for path in self.libs],
                    "The library may not have been loaded yet"
                ])
                log.warn(msg)
                return None

            # Download library if debugging remote process
            path = self.local_path(found_path)

        library = EXE(path, checksec=False)
        self.set_range(library)
        self._libraries[name] = library
        return library
    @property
    def libraries(self) -> dict[str, EXE | None]:
        for name, file in self._libraries.items():
            if file is None:
                with context.silent:
                    self.access_library(name)
        return self._libraries
    # We can not rely on the expected file because in case of symlinks maps shows the real file and not the default name
    # Example:
    # root@4b5e4700a41b:/# ls -l /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    # lrwxrwxrwx 1 root root 10 Apr 23  2024 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 -> ld-2.28.so
    # Would show ld-2.28.so instead
    @property
    def ld(self) -> EXE | None:
        dbg = self.dbg
        if self._ld == -1:
            return None
        elif isinstance(self._ld, EXE):
            return self._ld
        elif not dbg.debugging or (self._exe is not None and self._exe.statically_linked):
            self._ld = -1
            return None
        elif self._ld is None:
            # We start from the bottom for QEMU that has both its loader and the one of the program being emulated
            for path, addresses in list(self.libs.items())[::-1]:
                if Path(path).stem.startswith("ld"): # handle mips ld.so.1
                    local_path = self.local_path(path)
                    if local_path is None:
                        log.warn(f"can not access {path} from remote server.")
                        self._ld = -1
                        return None
                    else:
                        self._ld = EXE(local_path, address=addresses[0], end_address=addresses[-1], checksec=False)
                        return self._ld
            else:
                log.warn_once("Can not find loader...")
                self._ld = -1
                return None
    @ld.setter
    def ld(self, elf_ld: EXE) -> None:
        self._ld = elf_ld
    # If we don't have the binary we may consider iterating over the libraries to find a name that doesn't start with lib or ld- [05/02/25]
    # I can not affort do get out of __init__ without all the files properly identified [19/10/26]
    @property
    def exe(self) -> EXE | None:
        dbg = self.dbg
        if dbg.gdb is not None and self._exe is not None and self._exe.address == 0:
            # Right now this is called only if the binary is PIE
            self.set_range(self._exe)

        return self._exe 
    # pwntools is a bit loose on what is included in the symbols. In particular all library functions used by the executable are also included with the address of the plt. We have to remove those.
    # When merging all symbols we can not guarantee which plt and got we are referring to, so I prefer to simply discard those symbols.
    # Previously I would delete those symbols from the ELF itself, but just to be clean let's make our own copy until we see that the performances are too bad.
    # Once every library has been loaded we can just cache all symbols. I don't cache intermediate steps because I assume they are all loaded around the same time. Assumption not valid when using dlopen. 
    # What do we do about global variables such as stdin and stdout that may overshadow each other ? So far I'm taking them of to be sure.
    # BUG: changing address of binaries doesn't update the symbol address. I can not give that responsibility to EXE though, so I must detect here a change in a clean way.
    @property
    def symbols(self) -> dict[str, int]:
        symbols = {}
        if self._symbols is None: # TODO add something like "or any(changed(self.files, address)"
            for name, address in self._exe.symbols.items():
                if name[:4] in ["got.", "plt."]:
                    continue
                if name in self._exe.plt and address == self._exe.plt[name]:
                    continue
                # A function of the binary can also have a GOT entry (aarch64 PIE loads main through the GOT)
                if name in self._exe.got and name not in self._exe.functions:
                    continue
                symbols[name] = address
            all_libraries_present = True
            for _, library in self.libraries.items():
                if library is not None:
                    for name, address in library.symbols.items():
                        if name[:4] in ["got.", "plt."]:
                            continue
                        # The libc also has a got and plt, so we can't blindly remove all the symbols in those tables.
                        # The criteria I use is that pwntools adds the symbols from the plt if they are not in the binary so they can be detected because the address of the symbol is the same as the plt.
                        if name in library.plt and address == library.plt[name]:
                            continue
                        # We still remove the global variables to prevent name collisions between different files.
                        if name in library.got and name not in library.plt:
                            continue
                        else:
                            symbols[name] = address
                else:
                    all_libraries_present = False
            if all_libraries_present:
                self._symbols = symbols
            else:
                return symbols
        return self._symbols
    # Given a name such as libc we want to find the exact library the program is using such as libc.so.6
    # The problem is that we may have libraries like libcrypto that also start with "libc"
    # The other problem is that - + and . are not allowed to find the library through dbg.<lib_name>
    # I will not worry about the +, but expect users to split their names before the library version, so before - 
    def library_fullname(self, name: str) -> str | None:

        if name in self._libraries:
            return name

        best_guess = None
        for library_name in self._libraries:
            # libc.so.6 -> libc, libc-2.31.so -> libc, ld-linux-x86-64.so.2 -> ld
            short_name = Path(library_name).name.split(".")[0].split("-")[0]
            if name == short_name:
                return library_name
            elif name in short_name:
                best_guess = library_name

        return best_guess
    # TODO take a library for relative addresses like libdebug
    # May want to increase the limit
    # Is there a reason to make it public ? [06/01/25]
    def parse_address(self, location: int | str) -> int:
        """
        parse symbols and relative addresses to return the absolute address

        If the binary is not PIE all addresses are assumed to be absolute.
        If the binary is PIE we assume all addresses that could belong to the binary to be absolute.
        The only addresses that are considered relative are the one who are not a valid address of the binary, but are small enough to fit in the binary. 
        """
        dbg = self.dbg
        if type(location) is int:
            address = location

            if not self._exe.pie:
                return address

            if not address in self.exe and address < self._exe.size: # NOTE: I'm not sure yet if we should only use only allow relative breakpoints in len(exe.data) or the whole range of pages allocated to the program [05/02/25]
                address += self._exe.address

        elif type(location) is str:
            function = location
            offset = 0
            if "+" in location:
                # die if more than 1 +, but that's your fault
                function, offset = [x.strip() for x in location.split("+")]
                offset = int(offset, 16) if "0x" in offset.lower() else int(offset)

            try:
                address = self.symbols[function] + offset
            except KeyError as e:
                if not self._exe.statically_linked and dbg.libc is None:
                    log.error("symbol %s not found in ELF", location)
                    log.error("The libc is not loaded yet. If you want to put a breakpoint there call load_libc() first!")
                elif not self._exe.statically_linked:
                    log.error("symbol %s not found in ELF or libc", location)
                else:
                    log.error("symbol %s not found in ELF", location)
                raise


        else:
            raise Exception(f"parse_breakpoint is asking what is the type of {location}")

        return address
    def reverse_lookup(self, address: int | str) -> str:
        if type(address) is str:
            return address
        elif type(address) is int:
            if address in self.symbols.values():
                function = list(self.symbols.keys())[list(self.symbols.values()).index(address)]
                return f"{function}({hex(address)})"
            else:
                return hex(address)
        else:
            raise NotImplementedError(f"reverse_lookup doesn't support {type(address)} as address: ({address})")
