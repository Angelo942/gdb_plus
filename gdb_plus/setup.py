from __future__ import annotations
from pwn import ELF, process
from gdb_plus.utils.exe import EXE

def identify_executable(target: int | str | ELF | process | list[str] | tuple[str, int], binary: ELF | str | None = None) -> EXE | None:
    # NOTE: If we know the binary we are sure that binary is defined and of type EXE. [23/01/25]
    # NOTE: Maybe it's good not to rely too much on ELF in case someone wants to use it for different kinds of executables. [08/07/24]
    # NOTE: Should context be the fail-safe or do we want to make it the default ? [23/01/25]
    # Ensure that we have a  binary defined with the exception of when the target is a list, pid or remote gdbserver.
    # We would like a way to download the binary from the gdbserver if we connect with a tuple. Detect the program with info program cmdline and then download [06/05/25]
    # The executable is not only needed for our context, but gdb does need it. It can usually recover it from the gdbserver, but not if we are using QEMU. [07/05/25]
    exe: EXE | None
    if isinstance(binary, EXE):
        exe = binary
    elif isinstance(binary, str) or isinstance(binary, ELF):
        exe = EXE(binary, checksec=False)
    elif binary is None:
        if isinstance(target, EXE):
            exe = target
        elif isinstance(target, str) or isinstance(target, ELF):
            exe = EXE(target, checksec=False)
        elif isinstance(target, process):
            exe = EXE(target.elf, checksec=False)
        elif isinstance(target, int) or isinstance(target, list) or isinstance(target, tuple):
            exe = None
        else:
            raise TypeError(f"target is of a type we don't recognise: {target=}: {type(target)}")

    else:
        raise TypeError(f"binary is of a type we don't recognise: {binary=}: {type(binary)}")
        
    return exe