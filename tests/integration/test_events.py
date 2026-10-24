"""Catchpoints (syscalls, load, fork, exec), strace/ltrace/ftrace and signals."""
from queue import Queue

import pytest
from pwn import context

from gdb_plus import SKIP_SYSCALL, Suspended
from support.targets import registers


def NO_CATCHPOINTS(test):
    """Catchpoints are gdb's: the legacy fork has none, gdb_plus doesn't use new libdebug's yet (test_catchpoints_need_gdb)"""
    test = pytest.mark.syscall_catchpoints(test)
    test = pytest.mark.not_applicable("libdebug", "the legacy libdebug fork has no catchpoints")(test)
    return pytest.mark.known_gap("new_libdebug", "catch_event() raises: libdebug's own catchpoints are not used yet")(test)


def STATIC(reason="the QEMU fixtures are static: no library is loaded"):
    return pytest.mark.not_applicable("qemu", reason)


# The freestanding QEMU fixtures (fixtures/src/freestanding.h) have no fork or exec
NO_PROCESSES = pytest.mark.untested("qemu", "the freestanding QEMU fixtures don't fork or exec")


@pytest.fixture
def dbg(debugger, basic, backend):
    return debugger(basic, aslr=False, backend=backend)


def _is_say_hi(d):
    return d.syscall_args[0] == 1 and d.read(d.syscall_args[1], 7) == b"syscall"


########################## SYSCALLS ##########################

@NO_CATCHPOINTS
def test_catch_syscall_entry_and_exit(dbg):
    """
    catch_syscall("write", callback) calls the callback twice per syscall: on entry (entry=True) and on exit
    (entry=False) with the kernel's return value, 16 bytes for say_hi().
    """
    events = Queue()

    def callback(d, entry):
        if _is_say_hi(d) or not entry:
            events.put((entry, d.return_value if not entry else None))
        return False
    dbg.catch_syscall("write", callback)
    dbg.p.sendline(b"x")
    dbg.c()
    first = [events.get(timeout=1) for _ in range(2)]
    assert first[0] == (True, None)
    assert first[1] == (False, 16)


@NO_CATCHPOINTS
def test_catch_syscall_rewrites_arguments(dbg):
    """
    A syscall callback can rewrite dbg.syscall_args on entry: pointing the buffer of say_hi()'s write to another string
    makes the program print "rewritten".
    """
    replacement = dbg.write(None, b"rewritten\n")

    def callback(d, entry):
        if entry and _is_say_hi(d):
            d.syscall_args[1] = replacement
            d.syscall_args[2] = 10
        return False
    dbg.catch_syscall("write", callback)
    dbg.c(wait=False)
    assert dbg.p.recvline(timeout=5) == b"rewritten\n"
    dbg.interrupt()

# BUG: Another race condition around interrupt. It returns too fast.
@NO_CATCHPOINTS
def test_skip_syscall(dbg):
    """
    Returning SKIP_SYSCALL from the entry callback cancels the syscall with a chosen return value: say_hi()'s message is
    never printed and the next line is the pid.
    """
    def callback(d, entry):
        if entry and _is_say_hi(d):
            d.return_value = 16
            return SKIP_SYSCALL
        return False
    dbg.catch_syscall("write", callback)
    dbg.c(wait=False)
    assert dbg.p.recvline(timeout=5) == b"pid %d\n" % dbg.pid
    dbg.interrupt()
    print(dbg.priority)


@NO_CATCHPOINTS
def test_skip_syscall_and_stop(dbg):
    """
    SKIP_SYSCALL | True cancels the syscall and also stops the script there: the process is in the libc's syscall()
    wrapper, and finish() leads back to say_hi().
    """
    def callback(d, entry):
        if entry and _is_say_hi(d):
            d.return_value = 16
            return SKIP_SYSCALL | True
        return False
    dbg.catch_syscall("write", callback)
    dbg.c()
    assert dbg.instruction_pointer not in dbg.exe or dbg.exe.statically_linked  # in syscall() of the libc
    for _ in range(3):  # i386 enters the kernel through the vdso: one more frame
        if dbg.symbols["say_hi"] <= dbg.instruction_pointer < dbg.symbols["ask_pid"]:
            break
        dbg.finish()
    assert dbg.symbols["say_hi"] <= dbg.instruction_pointer < dbg.symbols["ask_pid"]


@NO_CATCHPOINTS
def test_stop_when_the_syscall_returns(dbg):
    """
    A callback that stops only on exit (not entry) stops after getpid returned: the return value is the pid, and
    overwriting it changes what the program prints.
    """
    dbg.catch_syscall("getpid", lambda d, entry: not entry)
    dbg.c()
    assert dbg.return_value == dbg.pid
    dbg.return_value = 1234
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"pid 1234" in dbg.p.recvall(timeout=5)


@NO_CATCHPOINTS
def test_catch_exit_group(dbg):
    """
    Catching exit_group, a syscall that never returns, calls the callback on entry only and does not wait forever for an
    exit that never comes.
    """
    # The syscall never returns: the step out of it must not wait forever (set_strace catches it too)
    calls = []
    dbg.catch_syscall("exit_group", lambda d, entry: calls.append(entry) or False)
    dbg.p.sendline(b"x")
    dbg.c()
    assert calls == [True]
    assert b"result 374" in dbg.p.recvall(timeout=5)


@NO_CATCHPOINTS
def test_syscall_number(dbg, sysno):
    """
    Inside a syscall callback dbg.sys_num is the number of the syscall being made (handle_syscall is the alias of
    catch_syscall).
    """
    numbers = Queue()

    def callback(d, entry):
        if entry:
            numbers.put(d.sys_num)
        return False
    dbg.handle_syscall("getpid", callback)
    dbg.p.sendline(b"x")
    dbg.c()
    assert numbers.get(timeout=1) == sysno("getpid")


@NO_CATCHPOINTS
def test_delete_catch_syscall(dbg):
    """delete_catch_syscall() removes the catchpoint: a stopping callback on getpid no longer stops the program."""
    dbg.catch_syscall("getpid", lambda d, entry: True)
    dbg.delete_catch_syscall("getpid")
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


@NO_CATCHPOINTS
def test_strace(dbg, capfd):
    """
    set_strace(only=[...]) prints every getpid and write with their decoded arguments and return value, and nothing for
    the syscalls not listed (read).
    """
    dbg.set_strace(only=["getpid", "write"])
    dbg.b("main_end")  # see test_catch_exit_group
    dbg.p.sendline(b"x")
    dbg.c()
    output = capfd.readouterr().out
    assert "write(fd=1, buf='syscall says hi\\n', count=16) = 16" in output
    assert f"getpid() = {dbg.pid}" in output
    assert "read(" not in output


@NO_CATCHPOINTS
def test_strace_exclude(dbg, capfd):
    """set_strace(exclude=["write"]) prints every syscall except write."""
    dbg.set_strace(exclude=["write"])
    dbg.b("main_end")
    dbg.p.sendline(b"x")
    dbg.c()
    output = capfd.readouterr().out
    assert "getpid()" in output
    assert "write(" not in output


@NO_CATCHPOINTS
@pytest.mark.not_applicable("qemu", "qemu-user can't stop a guest blocked in a syscall: the interrupt waits for read() to return (gdb_plus warns about it)")
def test_resume_a_syscall_callback_interrupted_in_a_blocking_read(dbg):
    """
    The entry callback of a read() catchpoint returns False, so gdb_plus steps over the syscall, which blocks waiting for
    input. interrupt() ends the script's c(wait=False) but suspends that step, without the handler noticing. After the
    input and resume() the step ends and the exit callback receives the 4 bytes of the line; then the process stays
    stopped, since the continue is over.
    """
    events = Queue()
    reading = []

    def callback(d, entry):
        if entry and d.syscall_args[0] == 0:
            reading.append(True)
            events.put(("entry", None))
        elif not entry and reading:
            reading.clear()
            events.put(("exit", d.return_value))
        return False
    dbg.catch_syscall("read", callback)
    done = dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    assert events.get(timeout=5) == ("entry", None)
    dbg.interrupt()
    assert done.is_set() and done.interrupted
    assert events.empty()
    dbg.p.sendline(b"abc")
    assert dbg.resume()
    assert dbg.wait(10)
    assert events.get(timeout=1) == ("exit", 4)
    assert not dbg.running and dbg.priority == 0


@NO_CATCHPOINTS
@pytest.mark.not_applicable("qemu", "qemu-user can't stop a guest blocked in a syscall: the interrupt waits for read() to return (gdb_plus warns about it)")
def test_continue_is_refused_while_a_syscall_callback_is_suspended(dbg):
    """
    The same read() catchpoint interrupted in the middle of its step: c() raises Suspended, since it would take the stop
    the suspended step waits for. After the input and resume() the handler finishes, and c() runs the program to its end.
    """
    entered = Queue()

    def callback(d, entry):
        if entry and d.syscall_args[0] == 0:
            entered.put(True)
        return False
    dbg.catch_syscall("read", callback)
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    assert entered.get(timeout=5)
    dbg.interrupt()
    with pytest.raises(Suspended):
        dbg.c()
    dbg.p.sendline(b"abc")
    assert dbg.resume()
    assert dbg.wait(10)
    dbg.c()
    assert b"line abc" in dbg.p.recvall(timeout=5)


@pytest.mark.not_applicable("gdb_only", "this test checks that catch_syscall() raises without gdb; where gdb is used catchpoints work (the other tests of this file)")
def test_catchpoints_need_gdb(dbg):
    """On the libdebug backends catch_syscall() raises instead of doing nothing: catchpoints only exist with gdb."""
    with pytest.raises(Exception):
        dbg.catch_syscall("write")


########################## OTHER EVENTS ##########################

@NO_CATCHPOINTS
@STATIC()
def test_catch_load(debugger, basic, backend):
    """
    catch("load") on a process started before the loader stops when a shared library is loaded; dbg.libc then exists.
    """
    dbg = debugger(basic, from_entry=False, backend=backend)
    assert dbg.libc is None
    dbg.catch("load")
    dbg.c()
    assert dbg.libc is not None


@pytest.mark.known_gap("libdebugs", "load_libc() waits with catch(\"load\"), a gdb catchpoint")
@STATIC()
def test_load_libc(debugger, basic, backend):
    """
    load_libc() on a process started before the loader runs it until the libc is mapped, so that libc symbols (malloc)
    can get breakpoints.
    """
    dbg = debugger(basic, from_entry=False, backend=backend)
    assert dbg.libc is None
    dbg.load_libc()
    assert dbg.libc is not None
    dbg.b("malloc")


@NO_CATCHPOINTS
@NO_PROCESSES
def test_catch_fork(debugger, target_binary, backend):
    """catch_event("fork") stops the parent on its fork (the forking fixture calls fork once)."""
    dbg = debugger(target_binary("forking"), backend=backend)
    seen = []
    dbg.catch_event("fork", lambda d: seen.append(d.instruction_pointer) or True)
    dbg.c()
    assert len(seen) == 1


@NO_CATCHPOINTS
@NO_PROCESSES
def test_catch_exec(debugger, target_binary, backend):
    """
    catch_event("exec") stops on the execve of the execs fixture; after delete_catch("exec") the new program runs to its
    end.
    """
    dbg = debugger(target_binary("execs"), backend=backend)
    dbg.catch_event("exec")
    dbg.c()
    assert b"before exec" in dbg.p.recvline(timeout=5)
    dbg.delete_catch("exec")
    dbg.c()
    assert b"after exec" in dbg.p.recvall(timeout=5)


@NO_CATCHPOINTS
@NO_PROCESSES
def test_syscall_callbacks_across_exec(debugger, target_binary, backend):
    """
    A callback on execve gets its entry and its exit even though the exit happens in the new program, and the new
    program then runs normally.
    """
    # The single step out of execve ends on the syscall exit catchpoint instead of a step trap
    dbg = debugger(target_binary("execs"), backend=backend)
    calls = []
    dbg.catch_syscall("execve", lambda d, entry: calls.append(entry) or False)
    dbg.c()
    assert calls == [True, False]
    assert b"after exec" in dbg.p.recvall(timeout=5)


########################## TRACING ##########################

@STATIC("the QEMU fixtures are static: no PLT to trace")
def test_ltrace(debugger, basic, backend, capfd):
    """
    set_ltrace() prints every libc call made through the PLT with its arguments (malloc(0x20)), honours exclude=, and
    disable_ltrace() removes all its breakpoints.
    """
    dbg = debugger(basic, backend=backend)
    dbg.set_ltrace(exclude=["setvbuf"])
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    output = capfd.readouterr().out
    assert "malloc['0x20'" in output
    assert "setvbuf" not in output
    dbg.disable_ltrace()
    assert all(bp.address not in dbg.exe.plt.values() for bps in dbg.control.breakpoints.values() for bp in bps)


def test_ftrace_with_custom_callback(debugger, basic, backend):
    """
    set_ftrace(custom_callback=) calls the callback with the name of every function of the binary that is entered (main,
    add, many_args, outer, inner), except the excluded ones.
    """
    dbg = debugger(basic, backend=backend)
    called = Queue()
    dbg.set_ftrace(custom_callback=lambda d, name: called.put(name) or False, exclude=["tick"])
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    names = []
    while not called.empty():
        names.append(called.get())
    assert {"main", "add", "many_args", "outer", "inner"} <= set(names)
    assert "tick" not in names
    dbg.disable_ftrace()
    dbg.p.sendline(b"x")


def test_ftrace_prints_arguments_and_return(debugger, basic, backend, capfd):
    """set_ftrace(n_args=2) prints each call with its first two arguments: add(0x1, 0x2)."""
    dbg = debugger(basic, backend=backend)
    dbg.set_ftrace(n_args=2, no_return=True)
    dbg.b("many_args")
    dbg.c()
    assert "add['0x1', '0x2']" in capfd.readouterr().out


########################## SIGNALS ##########################

@pytest.fixture
def signals(debugger, target_binary, backend):
    return debugger(target_binary("signals"), backend=backend)


@pytest.mark.known_gap("mips", "stop_signal uses the x86 numbers: SIGUSR1 is 16 on mips")
@pytest.mark.known_gap("mips64", "stop_signal uses the x86 numbers: SIGUSR1 is 16 on mips")
def test_signal_stops_the_process(signals):
    """
    A signal the program raises (SIGUSR1 in the signals fixture) stops the process; _stop_reason names it and
    stop_signal is its number for that architecture.
    """
    signals.c()
    assert signals._stop_reason == "SIGUSR1"
    assert signals.stop_signal == (16 if context.arch.startswith("mips") else 10)


@pytest.mark.known_gap("new_libdebug", "the stop handler ignores _handled_signals")
def test_handle_signal_by_name(signals):
    """
    handle_signal("SIGUSR1", callback) runs the callback when the signal arrives, and the program never receives it (its
    handler counts 0).
    """
    seen = []
    signals.handle_signal("SIGUSR1", lambda d: seen.append(d.stop_signal) or False)
    signals.c()
    assert seen == [10]
    assert b"usr1 0" in signals.p.recvall(timeout=5)  # nopass: the program never sees it


def test_handle_signal_by_number(signals):
    """handle_signal(10, callback) is the same as by name: the callback runs once."""
    seen = []
    signals.handle_signal(10, lambda d: seen.append(1) or False)
    signals.c()
    assert seen == [1]

# BUG: SIGUSR1 is registered by the program, so we shouldn't block the execution
def test_continue_until_across_a_signal(signals):
    """
    continue_until() to a location reached after a signal: the signal is delivered (the handler runs once) and
    continue_until still stops at the target.
    """
    # raise(SIGUSR1) happens before quiet_spot: the signal must not leave continue_until waiting forever
    signals.until("quiet_spot_body")
    assert signals.instruction_pointer == signals.symbols["quiet_spot_body"]
    assert signals.read_int(signals.symbols["usr1_count"]) == 1


@pytest.mark.known_gap("new_libdebug", "signal() never forwards the signal to libdebug")
def test_send_signal(signals):
    """
    signal("SIGUSR2") delivers a signal to the stopped process: its handler runs and the process stops again where it
    was.
    """
    signals.c()  # the SIGUSR1 raised by the program
    signals.until("quiet_spot_body")
    address = signals.instruction_pointer
    signals.signal("SIGUSR2")
    assert signals.instruction_pointer == address  # back where we were once the handler returned
    assert signals.read_int(signals.symbols["usr2_count"]) == 1


@pytest.mark.known_gap("new_libdebug", "signal() never forwards the signal to libdebug")
def test_send_signal_and_step_into_the_handler(signals):
    """signal("SIGUSR2", step=True) delivers the signal and stops on the first instruction of its handler."""
    signals.c()
    signals.until("quiet_spot_body")
    signals.signal("SIGUSR2", step=True)
    assert signals.instruction_pointer == signals.symbols["on_usr2"]


def test_fault(debugger, target_binary, backend):
    """
    A segmentation fault stops the process with _stop_reason SIGSEGV and the instruction pointer inside the crashing
    function.
    """
    path = target_binary("signals")
    dbg = debugger([path, "crash"], binary=path, backend=backend)
    dbg.c()
    assert dbg._stop_reason == "SIGSEGV"
    assert dbg.symbols["crash"] < dbg.instruction_pointer < dbg.symbols["main"]


########################## MORE OPTIONS ##########################

def _parent_pid(pid):
    """Field 4 of /proc/<pid>/stat (under QEMU: the parent of the emulator, which is what the guest's getppid sees)"""
    return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])


@NO_CATCHPOINTS
def test_sys_num_can_be_rewritten_on_entry(dbg, sysno):
    """
    Assigning dbg.sys_num on the entry of getpid turns it into getppid: the program prints its parent's pid (read from
    /proc) instead of its own.
    """
    parent = _parent_pid(dbg.pid)  # before the process exits

    def callback(d, entry):
        if entry:
            d.sys_num = sysno("getppid")
        return False
    dbg.catch_syscall("getpid", callback)
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"pid %d\n" % parent in dbg.p.recvall(timeout=5)


@NO_CATCHPOINTS
def test_catching_a_syscall_twice_replaces_the_callback(dbg):
    """A second catch_syscall() on the same syscall replaces the first callback instead of adding a catchpoint."""
    calls = []
    dbg.catch_syscall("getpid", lambda d, entry: calls.append("first") or False)
    dbg.catch_syscall("getpid", lambda d, entry: calls.append("second") or False)
    dbg.p.sendline(b"x")
    dbg.c()
    assert calls == ["second", "second"]  # entry and exit


@pytest.mark.known_gap("new_libdebug", "the stop handler ignores _handled_signals")
@pytest.mark.known_gap("libdebug", "the legacy libdebug never wakes the script after a signal handled by handle_signal() (test_handle_signal_by_name fails the same way)", run=False)
def test_handle_signal_callback_can_stop(signals):
    """
    A handle_signal() callback that returns True stops the process on the signal (in raise()); the program still never
    receives it.
    """
    signals.handle_signal("SIGUSR1", lambda d: True)
    signals.c()
    assert signals._stop_reason == "SIGUSR1"
    signals.c()
    assert b"usr1 0" in signals.p.recvall(timeout=5)


@pytest.mark.known_gap("new_libdebug", "signal() never forwards the signal to libdebug")
@pytest.mark.known_gap("i386", "signal() never comes back from the handler on this target (test_send_signal fails the same way)", run=False)
@pytest.mark.known_gap("aarch64", "signal() never comes back from the handler on this target (test_send_signal fails the same way)", run=False)
def test_send_signal_with_a_breakpoint_in_the_handler(signals):
    """
    signal("SIGUSR2", handler=on_usr2) (for handlers that rewrite the code where we stopped) puts the breakpoint in the
    handler instead and still stops back where we were once the handler returned.
    """
    signals.c()
    signals.until("quiet_spot_body")
    address = signals.instruction_pointer
    signals.signal("SIGUSR2", handler="on_usr2")
    assert signals.instruction_pointer == address
    assert signals.read_int(signals.symbols["usr2_count"]) == 1


@pytest.mark.known_gap("gdb_only", "c(signal=) is dropped with gdb: GdbBackend.cont has no signal parameter (debugger/engines/gdb.py:cont)")
@pytest.mark.known_gap("libdebug", "continue_until() across a signal never returns with the legacy libdebug (test_continue_until_across_a_signal fails the same way)", run=False)
@pytest.mark.known_gap("new_libdebug", "gdb_plus doesn't ask new libdebug to stop on signals: the SIGUSR1 raised by the program never stops it and it runs to its end")
def test_continue_with_a_signal(signals):
    """c(signal=SIGUSR2) resumes the process by delivering SIGUSR2: its handler runs once before the program ends."""
    signals.c()
    signals.until("quiet_spot_body")
    signals.c(signal=17 if context.arch.startswith("mips") else 12)
    assert b"usr1 1 usr2 1" in signals.p.recvall(timeout=5)


@STATIC("the QEMU fixtures are static: no PLT to trace")
@pytest.mark.known_gap("i386", "set_ltrace() stops tracing after the call to syscall() on i386: malloc is never printed (test_ltrace fails the same way)")
def test_ltrace_with_a_custom_calling_convention(debugger, basic, backend, capfd):
    """
    set_ltrace(calling_convention=[ip], n_args=1, no_return=True) prints the chosen register for each call: the
    instruction pointer, which is the PLT entry of the function, and no return value.
    """
    dbg = debugger(basic, backend=backend)
    dbg.set_ltrace(calling_convention=[registers()["ip"]], n_args=1, no_return=True)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    output = capfd.readouterr().out
    assert f"malloc['{dbg.exe.plt['malloc']:#x}']" in output
    assert "->" not in output


@pytest.mark.known_gap("libdebug", "set_ftrace() never reaches the next stop with the legacy libdebug (test_ftrace_with_custom_callback fails the same way)", run=False)
def test_ftrace_with_a_custom_calling_convention(debugger, basic, backend, capfd):
    """
    set_ftrace(calling_convention=[ip], n_args=1) prints the chosen register for each function entered: the
    instruction pointer, which is the address of add().
    """
    dbg = debugger(basic, backend=backend)
    dbg.set_ftrace(calling_convention=[registers()["ip"]], n_args=1, no_return=True)
    dbg.b("many_args")
    dbg.c()
    assert f"add['{dbg.symbols['add']:#x}']" in capfd.readouterr().out
