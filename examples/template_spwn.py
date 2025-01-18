#!/usr/bin/env python3
from gdb_plus import *

binary_name = "{binary}"
exe  = ELF(binary_name, checksec=True)
libc = ELF("{debug_dir}/{libc}", checksec=False)
context.binary = exe

# Needed if script is run from text editor instead of terminal
# I use ubuntu's default terminal
context.terminal = ["x-terminal-emulator", "-e"]

IP = ""
PORT = 0

# $ "./exploit.py" runs locally with gdb open
# $ "./exploit.py NOPTRACE" runs locally without gdb
# $ "./exploit.py REMOTE" connects to the remote server
dbg = Debugger(f"{debug_dir}/{{binary_name}}", aslr=False).setup_remote(IP, PORT)
p = dbg.p
dbg.c(wait=False) # Optional

ru  = lambda *x, **y: p.recvuntil(*x, **y)
rl  = lambda *x, **y: p.recvline(*x, **y)
rc  = lambda *x, **y: p.recv(*x, **y)
sla = lambda *x, **y: p.sendlineafter(*x, **y)
sa  = lambda *x, **y: p.sendafter(*x, **y)
sl  = lambda *x, **y: p.sendline(*x, **y)
sn  = lambda *x, **y: p.send(*x, **y)
bstr = lambda x: str(x).encode()

def main():
    pass

if __name__ == "__main__":
    main() 
    dbg.p.interactive()