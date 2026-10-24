# TEMPORARY repro of the test_qemu_gdbserver[riscv32] teardown hang. Delete after use.
import os
import traceback

from support.local_server import free_port


def test_repro(debugger, fixture_binary):
    from pwn import ELF, context, which
    basic = fixture_binary("basic_riscv32")
    port = free_port()
    emulator = which("qemu-riscv32")
    with context.local(binary=ELF(emulator, checksec=False)):
        qemu = debugger([emulator, "-g", str(port), basic], binary=emulator, backend="remote")
        qemu.c(wait=False)
    with context.local(binary=ELF(basic, checksec=False)):
        dbg = debugger(("127.0.0.1", port), binary=basic, qemu_gdbserver=qemu)
        try:
            start, end = dbg.libs[dbg.exe.path]
            print("libs", hex(start), hex(end), "entry", hex(dbg.exe.entry))
        except BaseException:
            print("TEST BODY FAILED:\n" + traceback.format_exc())
        gdb_pid = dbg.gdb.pid if hasattr(dbg.gdb, "pid") else None
        print("qemu running?", qemu.running, "guest running?", dbg.running)
        try:
            dbg.detach()
            print("guest detach OK")
        except BaseException:
            print("GUEST DETACH RAISED:\n" + traceback.format_exc())
        from gdb_plus.debugger.engines import GdbBackend
        print("guest gdb finalizer still pending:", dbg._backend_of(GdbBackend)._finalizer is not None)
        os.system("ps -eo pid,ppid,stat,args | grep -E 'gdb-multiarch|qemu-riscv32' | grep -v grep | cut -c1-140")
