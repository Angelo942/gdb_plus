# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
# Redundant with context. May be still used for path and address, but I would remove it.

from pwn import *
from threading import Event, Lock
from queue import Queue
from dataclasses import dataclass

DEBUG = False
_logger = logging.getLogger("gdb_plus")

# Only support amd64
class user_regs_struct:
    def __init__(self):
        # I should use context maybe... At least you don't have surprises like me when pack breaks [02/03/23]
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

class Fake_arguments:
    def __init__(self):
        pass

    def __getitem__(self, index: [int, slice]):
        #assert type(index) is int, "I can't handle slices to access multiple arguments"
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        return 0

    def __setitem__(self, index, value):
        pass

# Only works to read and set the arguments of the CURRENT function
class Arguments:
    def __init__(self, dbg):
        # Do we want to cache the registers and part of the stack ?
        # It would require to delete it when we execute an action
        self.dbg = dbg

    def __getitem__(self, index: [int, slice]):
        #assert type(index) is int, "I can't handle slices to access multiple arguments"
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            index -= len(calling_convention)
        # It would be better to force the user to save the arguments at the entry point and read them later instead... [25/07/23]
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            return unpack(self.dbg.read(pointer, context.bytes))
        elif context.arch in ["arm", "aarch64"]:
            pointer = self.dbg.stack_pointer + index * context.bytes
            return unpack(self.dbg.read(pointer, context.bytes))


    # How do we handle pushes ? Do I only write arguments when at the beginning of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        if type(index) is slice:
            for i, el in zip(range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step), value):
                self[i] = el
            return
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return setattr(self.dbg, register, value)
        else:
            index -= len(calling_convention)
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            self.dbg.write(pointer, pack(value))
        elif context.arch in ["arm", "aarch64"]:
            pointer = self.dbg.stack_pointer + index * context.bytes
            self.dbg.write(pointer, context.bytes)

class Arguments_syscall:
    def __init__(self, dbg):
        self.dbg = dbg

    def __getitem__(self, index: [int, slice]):
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        calling_convention = syscall_calling_convention[context.arch][1:] # The first one would have been the sys_num
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    # How do we handle pushes ? Do I only write arguments when at the beginning of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        if type(index) is slice:
            for i, el in zip(range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step), value):
                self[i] = el
            return
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            setattr(self.dbg, register, value)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

# Warning. Calling wait() before clear() returns immediately!
# TODO add a counter on when to stop treating return False as continues
class MyEvent(Event):
    def __init__(self):
        super().__init__()
        self.cleared = Event()
        #self.secret = Event()
        self.priority = 0
        self.pid = 0 # here to handle multiple processes under the same debugger. 
        self.flag_enforce_stop = None

    # I still need a standard wait for actions not initiated by dbg.cont and dbg.next
    # There seems to be a rare bug where multiple priorities are cleared at the same time [11/06/23]
    def priority_wait(self, comment = "", priority=None):
        if priority is None:
            priority = self.priority
        if DEBUG: _logger.debug(f"[{self.pid}] waiting with priority {priority} for {comment}")
        while True:
            # Unfortunately you can not use the number of threads waiting to find the max priority [18/06/23]
            super().wait()
            if DEBUG: _logger.debug(f"wait [{priority}] finished")
            if priority == self.priority:
                if DEBUG: _logger.debug(f"[{self.pid}] met priority {priority} for {comment}")
                # Prevent race conditions. Make sure all threads know the current priority before anyone calls lower_priority
                sleep(0.001)
                self.lower_priority(comment)
                # why does it work ?
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
        if DEBUG: _logger.debug(f"[{self.pid}] raising priority [{self.priority}] -> [{self.priority + 1}] for {comment}")
        self.priority += 1

    def lower_priority(self, comment):
        if DEBUG: _logger.debug(f"[{self.pid}] lowering priority [{self.priority - 1}] <- [{self.priority}] for {comment}")
        self.priority -= 1
        if self.priority < 0:
            log.warn(f"I think there is something wrong with the wait! We reached priority {self.priority}")
        if self.priority == 0:
            # Should reset when reaching 0, but also when debugging manually ? [18/06/23]
            if DEBUG: _logger.debug("reset enforce stop")
            self.flag_enforce_stop = None    

    # If we enforce a stop on level 5 through a breakpoint, a return False on level 7 should still continue, but not on level 3
    # If we enforce a stop because we are using gdb manually, a return False on level 7 should stop because we don't want to loose control, but not on level 3
    # Wait, I'm not convinced...
    @property
    def enforce_stop(self):
        if self.flag_enforce_stop is None:
            return False
        else:
            if DEBUG: _logger.debug(f"priority is {self.priority}. Enforce is {self.flag_enforce_stop}")
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

# Right now it's only an ELF, but we can consider extending it to PE for windows one day
# isinstance(obj, ELF) will accept bot EXE and ELF
class EXE(ELF):
    def __init__(self, path, address=None, end_address=None, **kwargs):
        if isinstance(path, ELF): 
            self.__dict__ = path.__dict__.copy()
            self.__class__ = EXE
        else:
            super().__init__(path, **kwargs)
        self.name = self.path.split("/")[-1]
        if address is not None: # pwntools already has an assumption for the initial address
            self.address = address
        self.end_address = end_address
        self.size = len(self.data)
        
    @ELF.address.setter
    def address(self, address):
        if self.address != 0 and self.address != address:
            log.warn("The base address of %s is not the one expected! Expected: %s. Received: %s", self.name, hex(self.address), hex(address))

        if address % 0x1000:
            log.warn("The address %s is not a multiple of the page size 0x1000. Are you sure this is your base address ?", hex(address))
        
        ELF.address.fset(self, address)

    # NOTE: What is the point of end_address = None if we set range to 0 and not None ? [05/02/25]
    # NOTE: We could set end_address to 0, but then we would have to worry about when address is set manually, but not end_address ? Not really I would say... [05/02/25]
    @property
    def range(self):
        if self.end_address is None:
            return 0
        return self.end_address - self.address

    def __contains__(self, value):
        if self.end_address is None:
            log.warn(f"I don't know which one is the last page of {self.name}. Please set end_address!")
            return False
        
        return self.address < value < self.end_address

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
        if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] wrapping {function_name}")
        return self

    def __enter__(self):
        if not self.owner.debugging:
            return
        #self.can_run.wait()
        with self.__lock:
            self.event.clear()
            self.counter += 1
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] entering lock with level {self.counter}")

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not self.owner.debugging:
            return
        with self.__lock:
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] exiting lock with level {self.counter}")
            self.counter -= 1
            # What about if we want to interrupt a continue until ? [21/06/23]
            if self.counter == 0:
                self.event.set()

def enum_libs(file):
    """
    Find which libraries will be used by an executable without having to run it. 
    """
    if file.statically_linked:
        return []

    # Get the .dynamic section (holds dynamic table entries)
    dynamic_section = file.get_section_by_name('.dynamic')
    if dynamic_section is None:
        print("No .dynamic section found. Is this a statically linked binary?")
        exit(1)
    data = dynamic_section.data()

    # Get the .dynstr section (holds dynamic strings)
    dynstr_section = file.get_section_by_name('.dynstr')
    if dynstr_section is None:
        print("No .dynstr section found!")
        exit(1)
    dynstr_data = dynstr_section.data()

    libs = []

    # Iterate over the dynamic table entries
    for i in range(0, len(data), context.bytes * 2):
        packed_tag, packed_val = data[i:i+context.bytes], data[i+context.bytes:i+context.bytes*2]
        if len(packed_val) < context.bytes:
            break
        tag, val = unpack(packed_tag), unpack(packed_val)
        # DT_NULL (tag 0) marks the end of the table
        if tag == 0:
            break
        # DT_NEEDED (tag 1) entries indicate required libraries
        if tag == 1:
            # 'val' is the offset into the .dynstr section for the library name
            end = dynstr_data.find(b'\x00', val)
            lib_name = dynstr_data[val:end].decode('utf-8')
            libs.append(lib_name)

    return libs
        
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
shellcode_sleep = {
    "amd64": b"\x90\xeb\xfe",
    "i386": b"\x90\xeb\xfe",
    "aarch64": b'\x1f\x20\x03\xd5\x00\x00\x00\x14',
    "arm": b'\x00\xf0\x20\xe3\xfe\xff\xff\xea',
}
# syscall / int 0x80 / svc #0
shellcode_syscall = {
    "amd64": b"\x0f\x05",
    "i386": b"\xcd\x80",
    "aarch64": b'\x01\x00\x00\xd4',
    "arm": b'\x00\x00\x00\xef',
    "riscv32": b's\x00\x00\x00',
    "riscv64": b's\x00\x00\x00',
    "mips": b'\x0c\x00\x00\x00',
}
# First register is where to save the syscall num
syscall_calling_convention = {
    "amd64": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
    "i386": ["rax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
    "aarch64": ["x8"]+[f"x{i}"for i in range(6)],
    "arm": ["r7"]+[f"r{i}"for i in range(7)],
    "riscv32": ["a7"]+[f"a{i}"for i in range(6)],
    "riscv64": ["a7"]+[f"a{i}"for i in range(6)],
    "mips": ["v0"] + [f"a{i}" for i in range(4)],
}
function_calling_convention = {
    "amd64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "i386": [],
    "aarch64": [f"x{i}"for i in range(8)],
    "arm": [f"r{i}"for i in range(4)],
    "riscv32": [f"a{i}"for i in range(8)],
    "riscv64": [f"a{i}"for i in range(8)],
    "mips": [f"a{i}" for i in range(4)],
}
return_instruction = {
    "amd64": b"\xc3",
    "i386": b"\xc3",
    "aarch64": b'\xc0\x03_\xd6',
    "arm": b'\x1e\xff\x2f\xe1',
    "riscv32": b'g\x80\x00\x00',
    "riscv64": b'g\x80\x00\x00',
    "mips": b'\x08\x00\xe0\x03',
}
nop = {
    "amd64": b"\x90",
    "i386": b"\x90",
    "aarch64": b'\x1f\x20\x03\xd5',
    "arm": b'\x00\xf0\x20\xe3',
    "riscv32": b'\x13\x00\x00\x00',
    "riscv64": b'\x13\x00\x00\x00',
    "mips": b'\x00\x00\x00\x00',
}
