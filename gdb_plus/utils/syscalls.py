from __future__ import annotations
import functools
from typing import TYPE_CHECKING
from pwn import constants, context

if TYPE_CHECKING:
    from typing import Callable, Sequence

# Argument kinds:
#   d  signed 32-bit int        l  signed register-sized int    u  unsigned decimal
#   x  hex                      o  octal                        p  pointer
#   s  C string                 v  NULL-terminated char*[]      m  mmap/mprotect prot
#   bN buffer whose length is argument number N (shown before the syscall runs)
SIGNATURES: dict[str, str] = {
    # files
    "read": "fd:d buf:p count:u",
    "write": "fd:d buf:b2 count:u",
    "pread64": "fd:d buf:p count:u offset:l",
    "pwrite64": "fd:d buf:b2 count:u offset:l",
    "readv": "fd:d iov:p iovcnt:d",
    "writev": "fd:d iov:p iovcnt:d",
    "open": "path:s flags:x mode:o",
    "openat": "dirfd:d path:s flags:x mode:o",
    "creat": "path:s mode:o",
    "close": "fd:d",
    "lseek": "fd:d offset:l whence:d",
    "stat": "path:s statbuf:p",
    "lstat": "path:s statbuf:p",
    "fstat": "fd:d statbuf:p",
    "newfstatat": "dirfd:d path:s statbuf:p flags:x",
    "fstatat": "dirfd:d path:s statbuf:p flags:x",
    "statx": "dirfd:d path:s flags:x mask:x statxbuf:p",
    "access": "path:s mode:o",
    "faccessat": "dirfd:d path:s mode:o flags:x",
    "readlink": "path:s buf:p bufsiz:u",
    "readlinkat": "dirfd:d path:s buf:p bufsiz:u",
    "getdents64": "fd:d dirp:p count:u",
    "getcwd": "buf:p size:u",
    "chdir": "path:s",
    "mkdir": "path:s mode:o",
    "rmdir": "path:s",
    "unlink": "path:s",
    "unlinkat": "dirfd:d path:s flags:x",
    "rename": "oldpath:s newpath:s",
    "chmod": "path:s mode:o",
    "ioctl": "fd:d request:x arg:x",
    "fcntl": "fd:d cmd:d arg:x",
    "dup": "oldfd:d",
    "dup2": "oldfd:d newfd:d",
    "dup3": "oldfd:d newfd:d flags:x",
    "pipe": "pipefd:p",
    "pipe2": "pipefd:p flags:x",
    "sendfile": "out_fd:d in_fd:d offset:p count:u",
    "memfd_create": "name:s flags:x",
    "poll": "fds:p nfds:u timeout:d",
    # memory
    "mmap": "addr:p length:x prot:m flags:x fd:d offset:x",
    "mmap2": "addr:p length:x prot:m flags:x fd:d pgoffset:x",
    "mprotect": "addr:p len:x prot:m",
    "munmap": "addr:p length:x",
    "mremap": "old_addr:p old_size:x new_size:x flags:x new_addr:p",
    "madvise": "addr:p length:x advice:d",
    "brk": "addr:p",
    # processes
    "execve": "path:s argv:v envp:p",
    "execveat": "dirfd:d path:s argv:v envp:p flags:x",
    "exit": "status:d",
    "exit_group": "status:d",
    "fork": "",
    "vfork": "",
    "wait4": "pid:d wstatus:p options:x rusage:p",
    "waitid": "idtype:d id:d infop:p options:x rusage:p",
    "kill": "pid:d sig:d",
    "tkill": "tid:d sig:d",
    "tgkill": "tgid:d tid:d sig:d",
    "getpid": "",
    "getppid": "",
    "gettid": "",
    "getuid": "",
    "geteuid": "",
    "getgid": "",
    "getegid": "",
    "ptrace": "request:d pid:d addr:p data:p",
    "prctl": "option:d arg2:x arg3:x arg4:x arg5:x",
    "arch_prctl": "code:x addr:p",
    "seccomp": "operation:d flags:x args:p",
    "process_vm_readv": "pid:d local_iov:p liovcnt:u remote_iov:p riovcnt:u flags:x",
    "process_vm_writev": "pid:d local_iov:p liovcnt:u remote_iov:p riovcnt:u flags:x",
    "set_tid_address": "tidptr:p",
    "set_robust_list": "head:p len:u",
    "rseq": "rseq:p rseq_len:u flags:x sig:x",
    "prlimit64": "pid:d resource:d new_limit:p old_limit:p",
    "futex": "uaddr:p op:x val:d timeout:p uaddr2:p val3:x",
    "uname": "buf:p",
    # signals
    "rt_sigaction": "signum:d act:p oldact:p sigsetsize:u",
    "rt_sigprocmask": "how:d set:p oldset:p sigsetsize:u",
    "rt_sigreturn": "",
    "sigaltstack": "ss:p old_ss:p",
    "alarm": "seconds:u",
    "pause": "",
    # time / randomness
    "nanosleep": "req:p rem:p",
    "clock_nanosleep": "clockid:d flags:x req:p rem:p",
    "clock_gettime": "clockid:d tp:p",
    "gettimeofday": "tv:p tz:p",
    "time": "tloc:p",
    "getrandom": "buf:p buflen:u flags:x",
    # sockets
    "socket": "domain:d type:x protocol:d",
    "connect": "sockfd:d addr:p addrlen:u",
    "bind": "sockfd:d addr:p addrlen:u",
    "listen": "sockfd:d backlog:d",
    "accept": "sockfd:d addr:p addrlen:p",
    "sendto": "sockfd:d buf:b2 len:u flags:x dest_addr:p addrlen:u",
    "recvfrom": "sockfd:d buf:p len:u flags:x src_addr:p addrlen:p",
}

@functools.cache
def syscall_names(arch: str) -> dict[int, str]:
    """{syscall number: name} for `arch`, taken from pwntools' SYS_* constants."""
    try:
        table = vars(getattr(constants.linux, arch))
    except AttributeError:
        return {}
    names: dict[int, str] = {}
    for key, value in table.items():
        name = key[4:]
        # i386 also defines SYS_SOCKET / SYS_socketcall_socket, which are
        # socketcall() sub-numbers that collide with the real syscall numbers
        if not key.startswith("SYS_") or name.isupper() or name.startswith("socketcall_"):
            continue
        number = int(value)
        if number not in names or (name in SIGNATURES and names[number] not in SIGNATURES):
            names[number] = name
    return names

MAX_BYTES: int = 0x40
MAX_ARGV: int = 8

def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value

def _quote(data: bytes, truncated: bool = False) -> str:
    return repr(data)[1:] + ("..." if truncated else "")

def _read_string(read_string: Callable[..., bytes], address: int) -> bytes | None:
    try:
        return read_string(address, limit=MAX_BYTES)
    except Exception:
        return None

def _format_argument(kind: str, value: int, values: Sequence[int], read: Callable[[int, int], bytes | None], read_string: Callable[..., bytes]) -> str:
    if kind == "d":
        return str(_signed(value, 32))
    if kind == "l":
        return str(_signed(value, context.bits))
    if kind == "u":
        return str(value)
    if kind == "o":
        return f"0{value:o}" if value else "0"
    if kind == "m":
        flags = [name for bit, name in ((1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")) if value & bit]
        if value & ~7 or not flags:
            return "PROT_NONE" if value == 0 else hex(value)
        return "|".join(flags)
    if kind == "x":
        return hex(value)

    # everything below is a pointer
    if value == 0:
        return "NULL"
    if kind == "s":
        string = _read_string(read_string, value)
        if string is not None:
            return _quote(string[:MAX_BYTES], truncated=len(string) >= MAX_BYTES)
    elif kind[0] == "b":
        length = values[int(kind[1:])]
        data = read(value, min(length, MAX_BYTES))
        if data is not None:
            return _quote(data, truncated=length > MAX_BYTES)
    elif kind == "v":
        strings: list[str] = []
        word = context.bits // 8
        for i in range(MAX_ARGV):
            raw = read(value + i * word, word)
            pointer = int.from_bytes(raw, context.endian) if raw else 0
            string = _read_string(read_string, pointer) if pointer else None
            if string is None:
                break
            strings.append(_quote(string[:MAX_BYTES], truncated=len(string) >= MAX_BYTES))
        else:
            strings.append("...")
        return "[" + ", ".join(strings) + "]"
    return hex(value)

def describe_syscall(number: int, values: Sequence[int], read: Callable[[int, int], bytes | None], read_string: Callable[..., bytes]) -> tuple[str, str]:
    """Format a syscall as 'name(arg=value, ...)' for the current context.arch.
    `read(address, size)` returns None on unreadable memory, `read_string(address, limit=...)` may raise.
    Returns (name, description)."""
    name = syscall_names(context.arch).get(number, f"syscall_{number}")
    signature = SIGNATURES.get(name)
    if signature is None:
        # unknown signature: we can't tell how many arguments are used, show them all
        arguments = [hex(value) for value in values]
    else:
        arguments = []
        for field, value in zip(signature.split(), values):
            argument, kind = field.split(":")
            arguments.append(f"{argument}={_format_argument(kind, value, values, read, read_string)}")
    return name, f"{name}({', '.join(arguments)})"
