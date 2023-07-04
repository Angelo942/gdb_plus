#!/usr/bin/env python3
from gdb_plus import *
from string import printable as alphabet

context.arch = 'amd64'

MAIN = 0x15de
CHECK_FLAG_CHILD = 0x1162
CHECK_FLAG_PARENT = 0x1392

# Each process will check some chars of the flag. But we don't know the order, so we dump it at runtime
full_data = []
def child_callback(self):
        full_data.append(self.rax)
        # rcx contains a byte calculated based on your flag, while rax is the byte that the program expects
        log.info(f"checking [{self.rax}] == [{self.rcx & 0xff}]")
        return False

def parent_callback(self):
        full_data.append(self.rax)
        log.info(f"checking [{self.rax}] == [{self.rcx & 0xff}]")
        return False

def emulate():
    global dbg, child
    # Set the debugger to attach to the child too
    dbg = Debugger("./challenges/nopeeking", debug_from=MAIN).set_split_on_fork(interrupt=True)
    flag = alphabet[:0x1b].encode()
    dbg.p.sendline(flag)
    dbg.cont()
    pid = dbg.wait_split()
    child = dbg.children[pid]
    # Debug with libdebug instead of gdb to go faster
    child.migrate(libdebug=True)
    dbg.migrate(libdebug=True)
    # Set your dump callbacks
    child.b(CHECK_FLAG_CHILD, callback=child_callback)
    dbg.b(CHECK_FLAG_PARENT, callback=parent_callback)
    # Set the debugger to emulate all calls to ptrace and waitpid. We don't want any logs so we set silent=False
    dbg.emulate_ptrace(silent=True)
    child.emulate_ptrace(silent=True)
    child.c(wait=False)
    dbg.c()

def generate_flag():
    flag = []
    for counter, data in enumerate(full_data):
        rax = (counter * 0x2c) % 0x100
        rdx = data
        flag.append(((rax ^ rdx) + (counter + 1) - 0x1a) % 0x100)
    flag = bytes(flag)
    return flag

if __name__ == "__main__":
    try:
        emulate()
    # Quando esce uno dei due processi lo script muore quindi so che ho leakato tutto
    except:
        print(generate_flag())
