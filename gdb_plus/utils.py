# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
# Redundant with context. May be still used for path and address, but I would remove it.

from pwn import *
from threading import Event, Lock
from queue import Queue
from dataclasses import dataclass

class user_regs_struct:
    def __init__(self):
        # I should use context maybe... At least you don't have suprises like me when pack breaks [02/03/23]
        self.registers = {64: ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_ax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]}[context.bits]
        self.size = len(self.registers)*context.bytes

    def set(self, data):
        for i, register in enumerate(self.registers):
            setattr(self, register, unpack(data[i*context.bytes:(i+1)*context.bytes])) # I said I don't like unpack, but shhh [02/03/23]
        return self

    def get(self):
        data = b""
        for register in self.registers:
            value = getattr(self, register, 0)
            data += pack(value)
        return data

    def __repr__(self):
        return ", ".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])

    def __str__(self):
        return "\n".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])


# Only works to read and set the arguments of the CURRENT function
class Arguments:
    def __init__(self, dbg):
        # Do we want to cache the registers and part of the stack ?
        # It would require to delete it when we execute an action
        self.dbg = dbg

    def __getitem__(self, index: int):
        assert type(index) is int, "I can't handle slices to access multiple arguments"
        self.dbg.restore_arch()
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            log.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            index -= calling_convention
        # It would be better to force the user to save the arguments at the entry point and read them later instead... [25/07/23]
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            return self.dbg.read(pointer, context.bytes)
        elif context.arch == "aarch64":
            pointer = self.dbg.stack_pointer + index * context.bytes
            return self.dbg.read(pointer, context.bytes)


    # How do we handle pushes ? Do I only write arguments when at the begining of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        self.dbg.restore_arch()
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            log.debug(f"argument {index} is in register {register}")
            return setattr(self.dbg, register, value)
        else:
            index -= calling_convention
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            return self.dbg.write(pointer, pack(value))
        elif context.arch == "aarch64":
            pointer = self.dbg.stack_pointer + index * context.bytes
            return self.dbg.write(pointer, context.bytes)

class Arguments_syscall:
    def __init__(self, dbg):
        self.dbg = dbg

    def __getitem__(self, index: int):
        assert type(index) is int, "I can't handle slices to access multiple arguments"
        self.dbg.restore_arch()
        calling_convention = syscall_calling_convention[context.arch][1:] # The first one would have been the sys_num
        if index < len(calling_convention):
            register = calling_convention[index]
            log.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    # How do we handle pushes ? Do I only write arguments when at the begining of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        self.dbg.restore_arch()
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            log.debug(f"argument {index} is in register {register}")
            return setattr(self.dbg, register, value)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

# Warning. Calling wait() before clear() returns immediatly!
# TODO add a counter on when to stop treating return False as continues
class MyEvent(Event):
    def __init__(self):
        super().__init__()
        self.cleared = Event()
        #self.secret = Event()
        self.priority = 0
        self.pid = 0
        self.flag_enforce_stop = None

    # I still need a standard wait for actions not initiated by dbg.cont and dbg.next
    # There seems to be a rare bug where multiple priorities are cleared at the same time [11/06/23]
    def priority_wait(self, comment = "", priority=None):
        if priority is None:
            priority = self.priority
        log.debug(f"[{self.pid}] waiting with priority {priority} for {comment}")
        while True:
            # Unfortunately you can not use the number of threads waiting to find the max priority [18/06/23]
            super().wait()
            log.debug(f"wait [{priority}] finished")
            # Make sure all threads know the current priority
            backup_priority = self.priority
            sleep(0.05)
            if priority == backup_priority:
                log.debug(f"[{self.pid}] met priority {priority} for {comment}")
                self.lower_priority(comment)
                # perchè non funzia ?
                #super().clear()
                break
            # If I call wait again while the event is set it won't block ! [04/04/23]
            self.cleared.wait()
            # I forgot to clear it somewhere... [22/05/23]
            # Wait, what happens if we have 3 threads waiting ??
            self.cleared.clear()
        #return priority

    # I move the priority -= 1 in here to avoid a race condition on the check priority == self.priority. I hope it won't break because I missed a clear somewhere, but with the cleared.wait; cleared.clear it should already break anyway [13/06/23]
    def clear(self, comment):
        #self.secret.clear()
        if self.is_set():
            super().clear()
            self.cleared.set()

    #def hidden_clear(self):
    #    if self.is_set():
    #        super().clear()
    #        self.cleared.set()

    def raise_priority(self, comment):
        log.debug(f"[{self.pid}] raising priority [{self.priority}] -> [{self.priority + 1}] for {comment}")
        self.priority += 1

    def lower_priority(self, comment):
        log.debug(f"[{self.pid}] lowering priority [{self.priority - 1}] <- [{self.priority}] for {comment}")
        self.priority -= 1
        if self.priority < 0:
            log.warn(f"I think there is something wrong with the wait! We reached priority {self.priority}")
        if self.priority == 0:
            # Should reset when reaching 0, but also when debugging manually ? [18/06/23]
            log.debug("reset enforce stop")
            self.flag_enforce_stop = None    

    # If we enforce a stop on level 5 through a breakpoint, a return False on level 7 should still continue, but not on level 3
    # If we enforce a stop because we are using gdb manually, a return False on level 7 should stop because we don't want to loose control, but not on level 3
    # Wait, I'm not convinced...
    @property
    def enforce_stop(self):
        if self.flag_enforce_stop is None:
            return False
        else:
            log.debug(f"priority is {self.priority}. Enforce is {self.flag_enforce_stop}")
            return self.priority >= self.flag_enforce_stop

@dataclass
class Inner_Breakpoint:
    byte: bytes = None
    temporary: bool = False

# I need a way to no if the process stopped due to my debugger or an action done manually
class Breakpoint:
    def __init__(self, breakpoint, address, callback = None, temporary = False, user_defined = True):
        self.native_breakpoint = breakpoint
        self.address = address
        self.callback = callback
        self.temporary = temporary
        self.user_defined = user_defined

class MyLock:
    def __init__(self, event, owner):
        self.owner = owner
        self.event = event
        self.counter = 0
        # prevent bugs with the counter ? [12/06/23]
        self.__lock = Lock()
        # Block from ptrace (strict interrupt)
        # I'm not sure if it makes sense. Maybe in the interrupt strict after having removed the lock there.
        #self.can_run = Event()
        #self.can_run.set()


    def log(self, function_name):
        #log.debug(f"[{self.owner.pid}] wrapping {function_name}")
        return self

    def __enter__(self):
        if not self.owner.debugging:
            return
        #self.can_run.wait()
        with self.__lock:
            self.event.clear()
            self.counter += 1
            log.debug(f"[{self.owner.pid}] entering lock with level {self.counter}")

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not self.owner.debugging:
            return
        with self.__lock:
            log.debug(f"[{self.owner.pid}] exiting lock with level {self.counter}")
            self.counter -= 1
            # What about if we want to interrupt a continue until ? [21/06/23]
            if self.counter == 0:
                self.event.set()
        
SIGNALS = {
       "SIGHUP":           1, 
       "SIGINT":           2, 
       "SIGQUIT":          3, 
       "SIGILL":           4, 
       "SIGTRAP":          5, 
       "SIGABRT":          6, 
       "SIGIOT":           6, 
       "SIGBUS":           7, 
    #    "SIGEMT":           -, 
       "SIGFPE":           8, 
       "SIGKILL":          9, 
       "SIGUSR1":         10, 
       "SIGSEGV":         11, 
       "SIGUSR2":         12, 
       "SIGPIPE":         13, 
       "SIGALRM":         14, 
       "SIGTERM":         15, 
       "SIGSTKFLT":       16, 
       "SIGCHLD":         17, 
    #    "SIGCLD":           -,  
       "SIGCONT":         18, 
       "SIGSTOP":         19, 
       "SIGTSTP":         20, 
       "SIGTTIN":         21, 
       "SIGTTOU":         22, 
       "SIGURG":          23, 
       "SIGXCPU":         24, 
       "SIGXFSZ":         25, 
       "SIGVTALRM":       26, 
       "SIGPROF":         27, 
       "SIGWINCH":        28, 
       "SIGIO":           29, 
       "SIGPOLL":         29, 
       "SIGPWR":          30, 
    #    "SIGINFO":          -,
    #    "SIGLOST":          -,
       "SIGSYS":          31, 
       "SIGUNUSED":       31, 
}

SIGNALS_from_num = ["I DON'T KNOW", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD",   "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGPOLL", "SIGPWR", "SIGSYS"]

## SHELLCODES
# test: nop; jmp test / nop; b 0x0
shellcode_sleep = {"amd64": b"\x90\xeb\xfe", "i386": b"\x90\xeb\xfe", "aarch64": b'\x1f \x03\xd5\x00\x00\x00\x14'}
# syscall / int 0x80 / svc #0
shellcode_syscall = {"amd64": b"\x0f\x05", "i386": b"\xcd\x80", "aarch64": b'\x01\x00\x00\xd4', "riscv": b's\x00\x00\x00'}
# First register is where to save the syscall num
syscall_calling_convention = {"amd64": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"], "i386": ["rax", "ebx", "ecx", "edx", "esi", "edi", "ebp"], "aarch64": ["x8"] + [f"x{i}" for i in range(6)], "riscv": ["a7"] + [f"a{i}" for i in range(6)]}
function_calling_convention = {"amd64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], "i386": [], "aarch64": [f"x{i}" for i in range(8)], "riscv": [f"a{i}" for i in range(8)]}
return_instruction = {"amd64": b"\xc3", "i386": b"\xc3", "aarch64": b'\xc0\x03_\xd6', "riscv": b'g\x80\x00\x00'}
nop = {"amd64": b"\x90", "i386": b"\x90", "aarch64": b'\x1f \x03\xd5', "riscv": b'\x13\x00\x00\x00'}