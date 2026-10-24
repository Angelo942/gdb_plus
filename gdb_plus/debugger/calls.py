from __future__ import annotations

from math import ceil
from queue import Queue
from typing import TYPE_CHECKING

from pwn import constants, context, log

from gdb_plus.utils import DEBUG, DoneEvent, set_done_if_panic, shellcode_syscall, syscall_calling_convention, function_calling_convention
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, IMPORTANT_DEBUG_OFF, context_decorator

if TYPE_CHECKING:
    from typing import Sequence

class CallsMixin(DebuggerBase):
    """
    Make the process call a function (call, gdb_call) or a syscall (syscall, make_page_rwx), then go back to where
    it stopped.
    """
    # For some reasons we get int3 some times
    # Now it's even worse. SIGABORT after that...
    def gdb_call(self, function: str, args: list[int], *, cast: str = "long") -> int | None:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return None
        if not self._exe.statically_linked:
            try:
                ans = self.execute(f"call ({cast}) {function} ({', '.join([hex(arg) for arg in args])})")
                if cast == "void":
                    ret = None
                else:
                    ans = ans.split()[-1]
                    # GEF prints logs as base 16, but pwndbg as base 10
                    ret = int(ans, 16) if "0x" in ans else int(ans)
            except Exception: #gdb.error: The program being debugged was signalled while in a function called from GDB.
                if DEBUG: self.logger.debug("gdb got int3 executing %s. Retrying...", function)
                self.finish()
                # For some reason I just get 0x0
                #return self.return_value()
                ret = self.gdb_call(function, args) # Should work this time
        elif function in self.symbols:
            ret = self.call(self.symbols[function], args)
            
        else:
            raise Exception(f"I don't know how to handle this function! {function} not in symbols")

        return ret

    def _convert_args(self, args: Sequence[int | str | bytes], heap: bool = True) -> tuple[list[int], list[tuple[int, int]]]:
        """
        Save any string present in the args and return a pointer to it instead
        """
        parsed_args, to_free = [], []
        
        for arg in args:
            if isinstance(arg, str):
                arg = arg.encode() + b"\x00"
            
            if isinstance(arg, bytes):
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False if you want me to save it in the BSS (experimental)")
                pointer = self.alloc(len(arg), heap=heap) # I should probably put the null byte only for string in case I have to pass a structure...
                to_free.append((pointer, len(arg))) #I include the length to virtually clear the bss too if needed (I won't set it to \x00 though)
                self.write(pointer, arg)
                arg = pointer

            parsed_args.append(arg)

        return parsed_args, to_free

    # CLAUDE recommendation to solve the fact that callbacks runs again when the function returns onto its breakpoint
    # If The return address of call() is the current pc the callback fires once when the function returns there and once more when restore_backup() sets pc through jump()
    # def _continue_call(self, backup: list[int], to_free: list[tuple[int, int]], heap: bool, end_pointer: int, return_value: Queue[int], alignment: int) -> None:
    #     # The function returns onto the instruction we called it from, and restore_backup() jumps there again.
    #     # If a user breakpoint is there (call() from its callback) it must not fire for either of them
    #     user_breakpoints = [breakpoint for breakpoint in self.breakpoints[end_pointer] if breakpoint.user_defined]
    #     saved_callbacks = [breakpoint.callback for breakpoint in user_breakpoints]
    #     for breakpoint in user_breakpoints:
    #         breakpoint.callback = lambda dbg: False
    #     try:
    #         #if end_pointer == self.instruction_pointer: # We called the function while on the first instruction, let's just step and continue normally [21/05/23] Wait, why bother ?
    #         # But this only works for intel processors. Use loop=True instead and you won't care if you started on the first instruction
    #         self.continue_until(end_pointer, loop=True)
    #         #while unpack(self.read(self.stack_pointer - context.bytes, context.bytes)) != end_pointer:
    #         #    assert self.instruction_pointer == end_pointer, "Something strange happened in a call"
    #         #    log.warn_once("Are you sure you called the function from outside ?")
    #         #    self.continue_until(end_pointer)

    #         if DEBUG: self.logger.debug("call finished")
                    
    #         res = self.return_value
    #         for _ in range(alignment):
    #             self.pop()
    #         self.restore_backup(backup)
    #     finally:
    #         for breakpoint, callback in zip(user_breakpoints, saved_callbacks):
    #             breakpoint.callback = callback
    #     for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
    #         self.dealloc(pointer, len=n, heap=heap)
    #     return_value.put(res) # will be the event that tells me I finished

    @set_done_if_panic
    def _continue_call(self, backup: list[int], to_free: list[tuple[int, int]], heap: bool, end_pointer: int, return_value: Queue[int], alignment: int, done: DoneEvent) -> None:
        #if end_pointer == self.instruction_pointer: # We called the function while on the first instruction, let's just step and continue normally [21/05/23] Wait, why bother ?
        # But this only works for intel processors. Use loop=True instead and you won't care if you started on the first instruction
        self.continue_until(end_pointer, loop=True)
        #while unpack(self.read(self.stack_pointer - context.bytes, context.bytes)) != end_pointer:
        #    assert self.instruction_pointer == end_pointer, "Something strange happened in a call"
        #    log.warn_once("Are you sure you called the function from outside ?")
        #    self.continue_until(end_pointer)

        if DEBUG: self.logger.debug("call finished")
                
        res = self.return_value
        for _ in range(alignment):
            self.pop()
        self.restore_backup(backup)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        return_value.put(res) # will be the event that tells me I finished

    # I still need end_pointer even if I would like to put the breakpoint on the address from which we call the function because I can't be sure that someone won't want to call a function from inside 
    # Wait, finish is doing it anyway... So let's require that call isn't used while you are inside the function, but still handle it just in case. Like a check that *(rsp - bytes) -> rip. It's not perfect, but it should at least always be true if we used the function properly [21/05/23]
    # TODO: check that we are not on a breakpoint. If we are check that we are not inside one of the callbacks. Disable it if we are so that it doesn't trigger again at the return. Maybe we should disable all callbacks, or all the ones at a lower level, but I still need to figure out the situation where it could happen [18/10/26]
    @context_decorator
    def call(self, function: int | str, args: list[int | str | bytes] = [], *, heap: bool = True, wait: bool = True, calling_convention: list[str] | None = None) -> int | Queue[int] | None:
        """
        Call any function in the binary with the parameters you want

        Parameters
        ----------
        function : int | str
            Pointer to the function to call
        args : list[int | str | bytes]
            List of parameters to pass to the function
            All strings passed this way will be saved in the binary with a null terminator
            Byte arrays will be saved as they are
        end_pointer : int, optional
            The function will run with a 'finish' command. If you aren't calling a standard function use this parameter. (I currently expect it to be a ret and will step on it to leave)
        heap : bool, optional
            Byte arrays and strings passed to the functions are by default saved on the heap with a malloc(). If you can't set this to False to save them on the bss (WARNING I can't guaranty I won't overwrite data this way)
        
        Return:
        return_value: [int, Queue]
        if wait = True the functions return the content of rax, otherwise the queue where it will be put once the function finishes
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # Before touching the registers: the call would have to resume the process
        self.control.priority.check_can_resume("call")
        address = self._parse_address(function)
        if calling_convention is None: calling_convention = function_calling_convention[context.arch]
        if DEBUG: self.logger.debug("calling %s", self.reverse_lookup(address))

        args, to_free  = self._convert_args(args, heap)

        #save registers 
        backup = self.backup()    
        
        for register in calling_convention:
            if len(args) == 0:
                break
            setattr(self, register, args.pop(0))
            
        # Libc functions may die otherwise. The stack must be aligned once the stack arguments are pushed:
        # o32 (mips): the caller reserves 4 words for the register arguments, the stack arguments come after them
        home_space = 4 if context.arch == "mips" else 0
        alignment = 0
        while (self.stack_pointer - (len(args) + home_space) * context.bytes) % 0x10 != 0x0:
            self.push(0)
            alignment += 1

        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args[::-1]:
            self.push(arg)
        for _ in range(home_space):
            self.push(0)
        
        return_address = self.instruction_pointer
        
        if context.arch in ["i386", "amd64"]:
            self.push(return_address)
        elif context.arch == "aarch64":
            self.x30 = return_address
        elif context.arch == "arm":
            self.lr = return_address
        elif context.arch in ["riscv32", "riscv64"]:
            self.ra = return_address
        elif context.arch in ["mips", "mips64"]:
            self.ra = return_address

        self.jump(address)
        
        return_value = Queue()
        # own=True: interrupt() suspends the call like an action of a callback instead of ending it, so that the registers are
        # restored only once the function has returned
        done = DoneEvent(self.control.priority)
        context.Thread(target=self.control.priority.inherit(self._continue_call, done, own=True), args=(backup, to_free, heap, return_address, return_value, alignment, done), name=f"[{self.pid}] call", daemon=True).start()
        if wait:
            done.wait()
            return return_value.get()
        else:
            done.wait_resumed()
            log.warn_once("you decided not to wait for the call to finish. I return a queue to the return value of the function. When you need it use .get() to wait for the call to finish")
            return return_value

    # Can not be cached because qemu somehow changes it back at every step! [16/01/25]
    @context_decorator
    def make_page_rwx(self, address: int, size: int = 1, *, syscall_address: int | None = None) -> None:
        """
        Sets the memory protections of a page to be readable, writable, and executable (RWX). 

        Args:
            address : int
                Any address within the page to update.
            size : OPTIONAL INT 
                Number of bytes that have to be executable. Set if the data may overlap multiple pages.
            syscall_address : OPTIONAL INT
                If running under QEMU without a symbol for mprotect we require the address of an executable syscall instruction.


        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        page_size = self.page_size
        page_address = address - address % page_size
        length = ceil((address + size - page_address) / page_size) * page_size

        if "mprotect" in self.symbols:
            self._backend.call_mprotect(page_address, length)
        elif context.arch not in ["riscv32", "riscv64"]:
            self.syscall(constants.SYS_mprotect.real, [page_address, length, constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE], syscall_address = syscall_address)
        else: # pwntools doesn't have constants yet for RISCV yet [18/01/25]
            self.syscall(226, [page_address, length, 7], syscall_address = syscall_address)

        
    # BUG: QEMU prevents overwriting code section even after mprotect [18/10/26] May be fixed in ubuntu 24+ (QEMU 8+)
    @context_decorator
    def syscall(self, code: int, args: list[int | str | bytes], *, heap: bool = True, syscall_address: int | None = None) -> int:
        """
        Make the program call a given syscall
        Under qemu restrictions apply. You must have the symbols for mprotect to make the code section writable or pass as an argument the address of a syscall instruction.

        Parameters
        ----------
        code : INT or pwnlib constant. 
            The syscall to call
        args : LIST of INT, pwnlib constants or STRING. 
            Arguments to the syscall. By default strings will be allocated to the heap

        syscall_address : INT, optional. 
            Address of a syscall. Used only if the program runs under qemu and you don't have the symbols for mprotect.
        """
        if DEBUG: self.logger.debug("syscall %d: %s", code, args)
        
        args = [code] + args

        shellcode = shellcode_syscall[context.arch]
        calling_convention = syscall_calling_convention[context.arch]

        assert len(args) <= len(calling_convention), "too many arguments for syscall"

        backup_registers = self.backup()
        return_address = self.instruction_pointer
        args, to_free = self._convert_args(args, heap)
        if syscall_address is not None:
            self.jump(syscall_address)

        else:
            # QEMU requires to call mprotect to write in executable memory [16/01/25]
            if not context.native:
                if "mprotect" not in self.symbols:
                    raise Exception("calling syscalls under qemu requires mprotect! Add the symbol or give me the address of a syscall instruction.")
                else: 
                    self.make_page_rwx(return_address, len(shellcode))
                    #pass # I will let write() call mprotect if needed [16/01/25]
        
            backup_memory = self.read(return_address, len(shellcode))
            self.write(return_address, shellcode)
        
        for register, arg in zip(calling_convention, args):
            if DEBUG: self.logger.debug("%s setted to %s", register, arg)
            setattr(self, register, arg)
        # Execute the syscall instruction
        self.step()
        res = self.return_value
        self.restore_backup(backup_registers)
        if syscall_address is None:
            self.write(return_address, backup_memory)
        self.jump(return_address)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        
        return res
