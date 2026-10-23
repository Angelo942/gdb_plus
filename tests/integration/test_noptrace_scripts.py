"""NOPTRACE: whole solve scripts written for debugging run unchanged with `python3 solve.py NOPTRACE`, without dying."""
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.not_applicable("libdebugs", "NOPTRACE starts no debugger at all: there is no libdebug backend to choose"),
    pytest.mark.not_applicable("remote", "NOPTRACE changes how a local binary is started: a gdbserver target is already started"),
    pytest.mark.untested("foreign", "NOPTRACE only changes how the process is started: covered on x86-64"),
]

# Appended to every script: what the test reads back, not part of what a user writes
FOOTER = '''
print("@@OUT", out.hex(), flush=True)
print("@@END", dbg.debugging, dbg.gdb is None, flush=True)
'''


def _run_script(tmp_path, source, binary, *switches):
    """Write the script next to the binary and run it as a user would: python3 solve.py NOPTRACE"""
    script = tmp_path / "solve.py"
    script.write_text(textwrap.dedent(source).lstrip() + FOOTER)
    env = dict(os.environ, PYTHONPATH=str(REPO), TARGET=str(binary), PWNLIB_NOTERM="1")
    return subprocess.run([sys.executable, str(script), *switches], cwd=tmp_path, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)


def _check(result, expected):
    """The script ended normally, never debugged, and the program printed what it prints alone"""
    output = result.stdout.decode(errors="replace")
    assert result.returncode == 0 and "Traceback" not in output, output
    assert "@@END False True" in output, output
    printed = bytes.fromhex(re.search(r"@@OUT ([0-9a-f]*)", output).group(1))
    # The scripts read up to "ready" before recvall: compare what comes after it
    assert _without_pid(printed) == _without_pid(expected).split(b"ready\n", 1)[-1]


def _without_pid(output):
    return re.sub(rb"pid \d+\n", b"", output)


@pytest.fixture
def run_noptrace(tmp_path, run_without_debugger):
    def run(source, binary, stdin):
        _check(_run_script(tmp_path, source, binary, "NOPTRACE"), run_without_debugger([binary], stdin))
    return run


def test_control_flow_script(run_noptrace, basic):
    """
    A script that breaks on functions (with callbacks, temporary), continues, finishes, steps, runs until labels,
    interrupts and waits, then talks to the program: with NOPTRACE every step is skipped and the program just runs.
    """
    run_noptrace('''
        from gdb_plus import *

        ticks = []
        def on_tick(dbg):
            ticks.append(dbg.read_long("counter"))
            return False

        dbg = Debugger(os.environ["TARGET"], aslr=False)
        dbg.b("tick", callback=on_tick)
        dbg.b("add", callback=lambda dbg: log.info(f"add({dbg.args[0]}, {dbg.args[1]})"))
        dbg.tb("outer")
        dbg.c()
        dbg.finish()
        dbg.step()
        dbg.si()
        dbg.next()
        dbg.ni()
        dbg.until("main_start")
        dbg.continue_until("say_hi")
        dbg.step_until_call()
        dbg.step_until_ret()
        dbg.step_until_address("ask_pid")
        log.info(f"stopped at {hex(dbg.instruction_pointer)} after {len(ticks)} ticks")
        dbg.delete_breakpoint("tick")
        dbg.c(wait=False)
        dbg.interrupt()
        dbg.wait()
        dbg.c(wait=False)
        dbg.p.recvuntil(b"ready\\n")
        dbg.p.sendline(b"noptrace")
        out = dbg.p.recvall(timeout=5)
        dbg.close()
    ''', basic, b"noptrace\n")


def test_memory_and_registers_script(run_noptrace, basic):
    """
    A script that reads and writes globals, strings and registers, uses the arguments, backs up and restores the
    registers, allocates, pushes and pops, patches with nops and looks at the canary and the libraries: with NOPTRACE
    the values are neutral (0, empty bytes) and none of it raises.
    """
    run_noptrace('''
        from gdb_plus import *

        dbg = Debugger(os.environ["TARGET"], aslr=False)
        dbg.until("after_input")
        counter = dbg.read_long("counter")
        greeting = dbg.read_string(dbg.read_pointer("greeting"))
        log.info(f"counter {counter:#x} greeting {greeting!r} buffer {dbg.read('buffer', 8)!r}")
        dbg.write("buffer", b"patched")
        dbg.write_long("counter", 1337)
        dbg.write_ints("table", [1, 2, 3])
        log.info(f"ip {dbg.instruction_pointer:#x} sp {dbg.stack_pointer:#x} ret {dbg.return_value:#x}")
        dbg.return_value = 0x1337
        dbg.args[0] = 5
        log.info(f"first argument {dbg.args[0]:#x}, syscall number {dbg.syscall_args[0]:#x}")
        saved = dbg.backup()
        dbg.restore_backup(saved)
        pointer = dbg.alloc(0x20)
        dbg.write(pointer, b"heap")
        dbg.dealloc(pointer)
        dbg.push(0x41)
        log.info(f"popped {dbg.pop():#x}")
        dbg.nop("tick")
        log.info(f"canary {dbg.canary!r}")
        log.info(f"libraries {list(dbg.libs)}")
        dbg.telescope()
        dbg.c(wait=False)
        dbg.p.recvuntil(b"ready\\n")
        dbg.p.sendline(b"noptrace")
        out = dbg.p.recvall(timeout=5)
        dbg.close()
    ''', basic, b"noptrace\n")


def test_calls_syscalls_and_events_script(run_noptrace, basic):
    """
    A script that calls functions of the program, makes syscalls, injects shellcode, catches syscalls, handles signals
    and turns on ltrace / ftrace: with NOPTRACE nothing is called nor caught and the program prints what it prints
    alone.
    """
    run_noptrace('''
        from gdb_plus import *

        def on_write(dbg, entry):
            log.info(f"write {'entry' if entry else 'exit'}")
            return False

        dbg = Debugger(os.environ["TARGET"], aslr=False)
        dbg.until("main_start")
        result = dbg.call("add", [1, 2])
        length = dbg.call("string_length", [b"four"])
        log.info(f"add -> {result}, string_length -> {length}")
        log.info(f"getpid -> {dbg.syscall(constants.SYS_getpid, [])}")
        dbg.make_page_rwx(dbg.symbols["tick"])
        dbg.inject_shellcode(asm(shellcraft.nop()))
        dbg.catch_syscall("write", on_write)
        dbg.handle_signal("SIGUSR1", lambda dbg: False)
        dbg.set_ltrace()
        dbg.set_ftrace()
        dbg.c(wait=False)
        dbg.p.recvuntil(b"ready\\n")
        dbg.p.sendline(b"noptrace")
        out = dbg.p.recvall(timeout=5)
        dbg.close()
    ''', basic, b"noptrace\n")


def test_fork_script(run_noptrace, fixture_binary):
    """
    A script that splits on fork, waits for the child, debugs it through dbg.children and emulates ptrace: with
    NOPTRACE there is nothing to split, both processes run and the parent reports the exit code of the child.
    """
    run_noptrace('''
        from gdb_plus import *

        dbg = Debugger(os.environ["TARGET"], aslr=False).set_split_on_fork()
        dbg.until("before_fork")
        dbg.c(wait=False)
        pid = dbg.wait_split()
        child = dbg.children[pid]
        child.b("child_work")
        child.c()
        child.c(wait=False)
        dbg.emulate_ptrace(silent=True)
        dbg.c(wait=False)
        out = dbg.p.recvall(timeout=5)
        dbg.close()
    ''', fixture_binary("forking"), b"")


def test_pwninit_template(tmp_path, run_noptrace, basic):
    """
    The pwninit template of examples/ (Debugger(...).setup_remote, dbg.c(wait=False), the send/receive shortcuts),
    filled for the fixture: `./exploit.py NOPTRACE` runs locally without gdb, as its comment says.
    """
    template = (REPO / "examples" / "template_pwninit.py").read_text()
    script = template.replace("{bindings}", 'exe = os.environ["TARGET"]').replace("{bin_name}", "exe") \
        .replace("{proc_args}", "exe").replace("    pass\n", '    sla(b"ready\\n", b"noptrace")\n') \
        .replace("    dbg.p.interactive()", "    out = dbg.p.recvall(timeout=5)")
    assert "out = " in script and "{" not in script.split("def main")[0].replace("{bindings}", ""), script
    run_noptrace(script, basic, b"noptrace\n")
