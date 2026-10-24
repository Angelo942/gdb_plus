from __future__ import annotations

from math import inf
from typing import TYPE_CHECKING

from pwn import context, log, pack, unpack

from gdb_plus.utils import DEBUG, shellcode_sleep, nop
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, IMPORTANT_DEBUG_OFF, context_decorator

if TYPE_CHECKING:
    from typing import Sequence
    from gdb import Inferior

class MemoryMixin(DebuggerBase):
    """
    The memory of the process: read / write and their typed variants (read_int, write_longs...), alloc / dealloc,
    push / pop, nop, the auxiliary vector and page_size, the canary, injected shellcode. Memory is accessible while
    the process runs.
    """
    @context_decorator
    def read(self, address: int, size: int, *, inferior: Inferior | None = None, pid: int | None = None) -> bytes:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return b"\x00" * size

        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = self.pid

        return self._backend.read(address, size, inferior, pid)

    def safe_read(self, address: int, size: int) -> bytes | None:
        """read() that returns None instead of raising on unmapped memory"""
        try:
            return self.read(address, size)
        except Exception:
            return None

    def _write_qemu_host(self, address: int, data: bytes) -> bool:
        """
        Write `data` at the guest `address` directly in the memory of the qemu-user process that emulates the program, at
        guest address + guest_base: /proc/<pid>/mem for a local qemu, the gdb attached to qemu (gdbserver_qemu) for a
        remote one. The protections of the guest pages don't apply there.
        Returns False, without writing, when the emulator's memory or guest_base aren't known.
        """
        if context.native or context.os == "baremetal" or not (self.local_debugging or self.pid is None):
            return False
        guest_base = self.space.find_qemu_guest_base(self.space.parse_maps(self._raw_maps()))
        if self.space._qemu_guest_base is None: # Writing at a guessed address could corrupt qemu itself
            return False
        if self.local_debugging:
            with open(f"/proc/{self.pid}/mem", "r+b", buffering=0) as mem:
                mem.seek(address + guest_base)
                mem.write(data)
        else:
            was_running = self.gdbserver_qemu.interrupt()
            self.gdbserver_qemu.write(address + guest_base, data)
            if was_running:
                self.gdbserver_qemu.c(wait=False)
        return True

    def write(self, address: int | None, data: bytes, *, inferior: Inferior | None = None, pid: int | None = None, heap: bool = True) -> int | None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 

        if address is None:
            address = self.alloc(len(data), heap=heap)
        
        if DEBUG: self.logger.debug("writing %s at 0x%x", data.hex(), address)
        
        # BUG: GDB may write in the wrong inferior...
        return self._backend.write(address, data, inferior, pid)

    # Names should be singular or plurals ? I wanted singular for read and plural for write but it should be consistent [02/06/23]
    # I assume little endianness [02/06/23]
    def _read_numbers(self, address: int | str, n: int, byte_size: int) -> list[int]:
        address = self._parse_address(address)
        data = self.read(address, n*byte_size)
        return [unpack(data[i*byte_size:(i+1)*byte_size], byte_size * 8) for i in range(n)]

    def read_bytes(self, address: int | str, n: int) -> list[int]:
        return self._read_numbers(address, n, 1)

    def read_byte(self, address: int | str) -> int:
        return self.read_bytes(address, 1)[0]

    def read_shorts(self, address: int | str, n: int) -> list[int]:
        return self._read_numbers(address, n, 2)

    
    def read_short(self, address: int | str) -> int:
        return self.read_shorts(address, 1)[0]

    def read_ints(self, address: int | str, n: int) -> list[int]:
        return self._read_numbers(address, n, 4)

    
    def read_int(self, address: int | str) -> int:
        return self.read_ints(address, 1)[0]

    def read_longs(self, address: int | str, n: int) -> list[int]:
        return self._read_numbers(address, n, 8)

    def read_long(self, address: int | str) -> int:
        return self.read_longs(address, 1)[0]

    def read_long_longs(self, address: int | str, n: int) -> list[int]:
        return self._read_numbers(address, n, 16)

    def read_long_long(self, address: int | str) -> int:
        return self.read_long_longs(address, 1)[0]

    @context_decorator
    def read_pointers(self, address: int | str, n: int) -> list[int]:
        return self.read_longs(address, n) if context.bits == 64 else self.read_ints(address, n)

    
    def read_pointer(self, address: int | str) -> int:
        return self.read_pointers(address, 1)[0]

    # Should we return the null bytes ? No, consistent with write_strings [02/06/23]
    def read_strings(self, address: int | str, n: int, *, limit: float = inf) -> list[bytes]:
        address = self._parse_address(address)
        chunk = 0x100
        data = b""
        current = address
        while data.count(b"\x00") < n and len(data) < limit:
            # Never read past the end of the page: the next one may not be mapped
            size = min(chunk, 0x1000 - current % 0x1000)
            try:
                data += self.read(current, size)
            except:
                log.warn("read_strings hit non accessible area")
                break
            current += size
        return data.split(b"\x00")[:n]

        
    def read_string(self, address: int | str, *, limit: float = inf) -> bytes:
        return self.read_strings(address, 1, limit=limit)[0]

    #def write_bit(self, address: int, )

    def _write_numbers(self, address: int | str | None, values: Sequence[int], byte_size: int, *, heap: bool = True) -> int | None:
        data = b"".join([pack(x, byte_size * 8) for x in values])
        if address is not None:
            address = self._parse_address(address)
        return self.write(address, data, heap = heap)

    def write_bytes(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self._write_numbers(address, values, 1, heap = heap)

    def write_byte(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_bytes(address, [value], heap = heap)

        
    def write_shorts(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self._write_numbers(address, values, 2, heap = heap)

    def write_short(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_shorts(address, [value], heap = heap)

    def write_ints(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self._write_numbers(address, values, 4, heap = heap)

    def write_int(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_ints(address, [value], heap = heap)

    def write_longs(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self._write_numbers(address, values, 8, heap = heap)

    def write_long(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_longs(address, [value], heap = heap)

    def write_long_longs(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self._write_numbers(address, values, 16, heap = heap)

    def write_long_long(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_long_longs(address, [value], heap = heap)

    @context_decorator
    def write_pointers(self, address: int | str | None, values: Sequence[int], *, heap: bool = True) -> int | None:
        return self.write_longs(address, values, heap = heap) if context.bits == 64 else self.write_ints(address, values, heap = heap)

    
    def write_pointer(self, address: int | str | None, value: int, *, heap: bool = True) -> int | None:
        return self.write_pointers(address, [value], heap = heap)

    # If the user has a byte array and doesn't want the null byte he would just write it himself, right ? [17/11/23] 
    def write_strings(self, address: int | str | None, values: Sequence[str | bytes], *, heap: bool = True) -> int:
        """
        save a list of strings after adding a null byte to all of them. 
        
        If address in None a pointer to the first string will be returned.
        """
        values = [value.encode() if type(value) is str else value for value in values]
        data = b"\x00".join(values) + b"\x00" # Better be safe than sorry. We are working with strings anyway, so who cares if we have one more byte [21/10/23]
        
        if address is None:
            address = self.alloc(len(data), heap=heap)
        else:
            address = self._parse_address(address)
        self.write(address, data)
        return address

    def write_string(self, address: int | str | None, value: str | bytes, *, heap: bool = True) -> int:
        """
        save a string after adding a null byte to it. 

        If address in None a pointer to the string will be returned.
        """
        return self.write_strings(address, [value], heap = heap)

    @context_decorator
    def push(self, value: int) -> None:
        """
        push value (must be uint) on the stack
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if DEBUG: self.logger.debug("pushing 0x%x", value)
        self.stack_pointer -= context.bytes
        self.write(self.stack_pointer, pack(value))

    @context_decorator
    def pop(self) -> int:
        """
        pop value (uint) from the stack
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        data = self.read(self.stack_pointer, context.bytes)
        self.stack_pointer += context.bytes
        return unpack(data)

    # alloc and dealloc instead of malloc and free because you may want to keep those names for function in your exploit

    # what is this error ??? [04/03/23]
    #gdb.error: The program being debugged was signalled while in a function called from GDB.
    #GDB remains in the frame where the signal was received.
    #To change this behaviour use "set unwindonsignal on".
    #Evaluation of the expression containing the function
    #(__GI___libc_malloc) will be abandoned.
    #When the function is done executing, GDB will silently stop.
    
    def alloc(self, n: int, /, *, heap: bool = True) -> int:
        """
        Allocate N bytes in the heap or [if really needed] the bss

        Parameters
        ----------
        n : int
            Size to allocate
        heap : bool, optional
            Set to False if you can't use the heap
            This way it will return a pointer to an area of the bss
        Returns
        -------
        pointer
        """
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return 0        

        if heap and "malloc" not in self.symbols:
            log.warn_once("Can not find malloc. Data will be allocated on the BSS!")
            heap = False

        if heap:
            ret = self._backend.alloc(n)
        else:
            if self._free_bss is None:
                self._free_bss = self._exe.bss() # I have to think about how to preserve eventual data already present
            ret = self._free_bss
            self._free_bss += n
        
        return ret

    def dealloc(self, pointer: int, len: int = 0, heap: bool = True) -> None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if heap:    
            self._backend.dealloc(pointer)
        else:
            # MMMMMMM, not perfect for different inferiors
            self._free_bss -= len

            #I know it's not perfect, but damn I don't want to implement a heap logic for the bss
            #Just use the heap if you can

    # We could make size round up to the start of next instruction, but should we ? [23/01/25]
    @context_decorator
    def nop(self, address: int | str, instructions: int = 1, *, size: int | None = None) -> bytes:
        address = self._parse_address(address)
        if size is None:
            code = self.disassemble(address, instructions*10)
            size = 0
            for i in range(instructions):
                size += next(code).size
        if size % len(nop[context.arch]) != 0:
            log.warn(f"I have to nop {size} bytes, but this is not divisible by the length of our nop instruction ({len(nop[context.arch])}).")
        backup = self.read(address, size)
        self.write(address, nop[context.arch] * (size // len(nop[context.arch])))
        return backup

    # taken from GEF to locate the canary
    @property
    def _auxiliary_vector(self) -> dict[str, int] | None:
        if not self._saved_auxiliary_vector:
            self._saved_auxiliary_vector = self._backend.auxiliary_vector()
        return self._saved_auxiliary_vector

    @property
    def page_size(self) -> int:
        """
        Size of a memory page in the process. 0x1000 almost everywhere, but aarch64 and mips kernels can use 16K or 64K pages.
        """
        if not self.debugging:
            return 0x1000
        auxiliary_vector = self._auxiliary_vector or {}
        return auxiliary_vector.get("AT_PAGESZ", 0x1000)

    # The canary is constant right ? This way you can also set it after a leak and access it from anywhere
    @property
    @context_decorator
    def canary(self) -> bytes | int:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        elif self._canary is None:
            auxval = self._auxiliary_vector
            canary_location = auxval["AT_RANDOM"]
            canary = self.read(canary_location, context.bytes)
            self._canary = b"\x00"+canary[1:]
        
        return self._canary

    # We can not search for the canary while gdb is running, so for now I only check if the canary is known. [24/04/24]
    @canary.setter
    def canary(self, value: bytes) -> None:
        if self.debugging and self._canary is not None and value != self._canary:
            # Do we want to backup the original value to make sure we don't warn for conflict between the values set by the user ? [24/04/24]
            log.warn(f"setting canary to: {value}, but debugger thinks canary is {self.canary}")
        self._canary = value

    # TODO if address set, return backup of area overwritten instead of address
    # TODO parameter "overwritable = False", if set to True save the memory region so that you can send other shellcodes without calling mprotect (Maybe set a larger area that simple len(shellcode) then)
    def inject_shellcode(self, shellcode: bytes, *, address: int | None = None, skip_mprotect: bool = False, inferior: Inferior | None = None) -> int:
        """
        Inject a shellcode in the binary.
        By default will allocate an area in the heap and make it executable

        Arguments:
            shellcode: bytes to inject
            address: address where to write. If not set will be allocated with malloc
            skip_mprotect: turn on this flag if the section is already executable
        """

        if self.gdb is not None:
            if inferior == None:
                inferior = self.current_inferior
            
            old_inferior = self.switch_inferior(inferior.num)

        if address is None:
            if DEBUG: self.logger.debug("allocating memory for shellcode")
            address = self.alloc(len(shellcode))

        if not skip_mprotect:
            self.make_page_rwx(address, len(shellcode))

        self.write(address, shellcode) # After make_page_rwx because in QEMU write may have to make the page writable anyway
        if self.gdb is not None and old_inferior is not None:
            self.switch_inferior(old_inferior.num)

        return address

    @context_decorator
    def inject_sleep(self, address: int, inferior: Inferior | None = None) -> bytes:
        """
        Inject a shellcode that stops the execution at a specific address

        Is meant to be used in the binary code, so it expects an address and returns the bytes that have been overwritten
        """
        #test:
        #jmp test
        # I put a nop to let step(force=True) work in case [29/04/23]
        shellcode = shellcode_sleep[context.arch]
        backup = self.read(address, len(shellcode), inferior=inferior)
        self.write(address, shellcode, inferior=inferior)
        return backup
