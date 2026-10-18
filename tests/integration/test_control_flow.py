"""step / next / finish / continue_until / jump / interrupt / wait on every backend."""
import time

import pytest

from support.targets import after_call, call_target, call_to, calls_in, is_call, is_return, read_c_long

# qemu-user only stops a guest between two instructions, not inside a host syscall
QEMU_BLOCKED_READ = pytest.mark.not_applicable("qemu", "qemu-user can't stop a guest blocked in a syscall: the interrupt waits for read() to return (gdb_plus warns about it)")

# next_inst sets is_call for every architecture but arm: next() and step_until_call() raise CsError there
# (inside next()'s thread: the call never returns), see also unit/test_registers_offline.py
ARM_IS_CALL = "next_inst has no is_call on arm: the capstone instruction raises CsError"
# mips: a call returns after its delay slot (call + 8), next() waits at call + 4
MIPS_DELAY_SLOT = "next() puts its breakpoint on the delay slot of the call (call + 4) instead of call + 8"


# riscv32's compressed call
RISCV_C_JAL = "next_inst.is_call only knows jal: the compressed call c.jal of riscv32 is stepped into"


def next_gaps(test):
    test = pytest.mark.known_gap("arm", ARM_IS_CALL, run=False)(test)
    for arch in ["mips", "mips64"]:
        test = pytest.mark.known_gap(arch, MIPS_DELAY_SLOT, run=False)(test)
    return test


def ret_gap(test):
    """step_until_ret() looks for the `ret` mnemonic: arm returns with bx lr / pop {pc}, mips with jr $ra, riscv with c.jr ra"""
    for arch in ["arm", "mips", "mips64", "riscv32", "riscv64"]:
        test = pytest.mark.known_gap(arch, "step_until_ret() only recognises the `ret` mnemonic")(test)
    return test


# finish() takes the return address from the link register on these architectures: right at the entry of a
# function only. Once the function has called something else, finish() waits for an address that never comes.
LINK_REGISTER = "finish() reads the return address from the link register (x30 / ra), overwritten by the function's own calls"


def link_register_gap(test):
    for arch in ["aarch64", "mips", "mips64", "riscv32", "riscv64"]:
        test = pytest.mark.known_gap(arch, LINK_REGISTER, run=False)(test)
    return test


@pytest.fixture
def dbg(debugger, basic, backend):
    return debugger(basic, aslr=False, backend=backend)


def test_step(dbg):
    """
    step() executes exactly one instruction: the instruction pointer moves by the size of the instruction it was on.
    """
    address, size = dbg.instruction_pointer, dbg.next_inst.size
    dbg.step()
    assert dbg.instruction_pointer == address + size


def test_step_force(dbg):
    """
    step(force=True) (and its old name exit_broken_function()) leaves the current address even when a breakpoint sits on
    it, without running that breakpoint's callbacks.
    """
    # force=True steps again when gdb stays on the same instruction (after a jump or a broken frame)
    dbg.until("add")
    hits = []
    dbg.b("add", callback=lambda d: hits.append(1) or False)
    address, size = dbg.instruction_pointer, dbg.next_inst.size
    dbg.step(force=True)
    assert dbg.instruction_pointer == address + size
    assert hits == [], "a forced step must not run the callbacks of the address it leaves"
    dbg.delete_breakpoint("add")
    dbg.jump("add")
    dbg.exit_broken_function()  # the old name of the forced step
    assert dbg.instruction_pointer == address + size


def test_step_repeat(dbg):
    """
    si(repeat=3) executes three instructions: the instruction pointer ends three instructions after the start of add().
    """
    dbg.until("add")
    dbg.si(repeat=3)
    assert dbg.instruction_pointer == dbg.symbols["add"] + sum(i.size for i in list(dbg.disassemble(dbg.symbols["add"], 0x20))[:3])


def test_continue_until_symbol(dbg):
    """continue_until("many_args") runs the process to that function and stops on its first instruction."""
    dbg.continue_until("many_args")
    assert dbg.instruction_pointer == dbg.symbols["many_args"]


def test_continue_until_offset(dbg):
    """
    until(integer) on a PIE treats the integer as an offset from the binary's base and stops at the runtime address.
    """
    if not dbg.exe.pie:
        pytest.skip("not applicable: an integer is an offset only in a PIE, in the others it is the address")
    dbg.until(dbg.symbols["many_args"] - dbg.exe.address)
    assert dbg.instruction_pointer == dbg.symbols["many_args"]


def test_continue_until_where_we_are_does_nothing(dbg):
    """
    until() to the address the process is already stopped on returns at once: tick() is not run again (counter stays 0).
    """
    dbg.until("tick")
    assert read_c_long(dbg, "counter") == 0
    dbg.until("tick")
    assert read_c_long(dbg, "counter") == 0


def test_continue_until_loop(dbg):
    """
    until(address, loop=True) from that same address runs until the next time it is reached: tick() runs once and stops
    on the second call.
    """
    dbg.until("tick")
    dbg.until("tick", loop=True)
    assert dbg.instruction_pointer == dbg.symbols["tick"]
    assert read_c_long(dbg, "counter") == 1


def test_continue_until_hardware(dbg):
    """until(..., hw=True) uses a hardware breakpoint to stop at the target."""
    dbg.until("tick", hw=True)
    assert dbg.instruction_pointer == dbg.symbols["tick"]


def test_non_blocking_continue_until(dbg):
    """
    until(..., wait=False) returns an event at once; it is set only after the program gets its input and reaches
    after_input.
    """
    done = dbg.until("after_input", wait=False)
    dbg.p.recvuntil(b"ready\n")
    assert not done.is_set()
    dbg.p.sendline(b"go")
    assert done.wait(10)
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_continue_to_the_end(dbg):
    """c() without breakpoints lets the program run to its end; its output matches what it prints without a debugger."""
    dbg.p.sendline(b"end")
    dbg.c()
    assert b"result 374 counter 5" in dbg.p.recvall(timeout=5)


@next_gaps
@pytest.mark.known_gap("riscv32", RISCV_C_JAL)
def test_next_steps_over_calls(dbg):
    """
    next() on a call instruction runs the whole called function and stops on the instruction the call returns to (after
    the delay slot on mips), with inner()'s return value 40.
    """
    call = call_to(dbg, "outer", "inner")
    dbg.until(call.address)
    dbg.next()
    assert dbg.instruction_pointer == after_call(call)
    assert dbg.return_value == 40


@pytest.mark.known_gap("arm", ARM_IS_CALL)
@pytest.mark.known_gap("riscv32", RISCV_C_JAL, run=False)
def test_step_until_call(dbg):
    """
    step_until_call() single steps from the start of outer() until the next instruction is the call to inner(), and
    stops on it.
    """
    call = call_to(dbg, "outer", "inner")
    dbg.until("outer")
    assert dbg.step_until_call() >= 0
    assert dbg.instruction_pointer == call.address
    assert dbg.next_inst.is_call


@pytest.mark.known_gap("arm", ARM_IS_CALL, run=False)
def test_next_is_a_step_on_other_instructions(dbg):
    """next() on an instruction that is not a call behaves like step(): one instruction."""
    dbg.until("add")
    address, size = dbg.instruction_pointer, dbg.next_inst.size
    dbg.ni()
    assert dbg.instruction_pointer == address + size


@pytest.mark.known_gap("arm", ARM_IS_CALL, run=False)
def test_next_repeat(dbg):
    """next(repeat=n) executes n instructions, stepping over calls, and ends on the expected instruction of outer()."""
    dbg.until("outer")
    instructions = list(dbg.disassemble(dbg.symbols["outer"], 0x40))
    dbg.next(repeat=len([i for i in instructions if i.address < instructions[0].address]) + 3)
    assert dbg.instruction_pointer == instructions[3].address


@pytest.mark.known_gap("arm", ARM_IS_CALL, run=False)
@pytest.mark.known_gap("riscv32", RISCV_C_JAL, run=False)
def test_non_blocking_next_over_a_read(dbg):
    """
    next(wait=False) over the call to fgets returns an event that stays clear while the program waits for input and is
    set once the line is sent.
    """
    fgets = calls_in(dbg, "main_start", "after_input")[-1]
    dbg.until(fgets.address)
    assert dbg.next_inst.is_call
    done = dbg.next(wait=False)
    assert not done.wait(1)  # fgets waits for the line
    dbg.p.sendline(b"typed")
    assert done.wait(10)
    assert dbg.instruction_pointer == after_call(fgets)


def test_finish(dbg):
    """
    finish() at the entry of inner() runs to the return address in outer() and the return value (40) is readable there.
    """
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    dbg.finish()
    assert dbg.instruction_pointer == return_address
    assert dbg.return_value == 40


@link_register_gap
def test_finish_from_inside_the_function(dbg):
    """
    finish() from the middle of outer(), after it called inner(): the return address must be found in the frame, not in
    the link register or on top of the stack.
    """
    # In outer, after its call to inner: the return address is neither on the top of the stack nor in the
    # link register any more (the call to inner overwrote it)
    return_address = after_call(call_to(dbg, "main", "outer", end="main_end"))
    dbg.until(after_call(call_to(dbg, "outer", "inner")))
    dbg.finish()
    assert dbg.instruction_pointer == return_address
    assert dbg.return_value == 41


def test_return_pointer(dbg):
    """dbg.return_pointer at the entry of inner() is the address the call returns to."""
    dbg.until("inner")
    assert dbg.return_pointer == after_call(call_to(dbg, "outer", "inner"))


@link_register_gap
def test_finish_repeat(dbg):
    """
    finish(repeat=2) from inner() returns out of inner and then out of outer, back in main, with outer's return value
    41.
    """
    dbg.until("inner")
    dbg.finish(repeat=2)
    assert dbg.return_value == 41
    assert dbg.symbols["main"] < dbg.instruction_pointer < dbg.symbols["main_end"]


def test_finish_hardware(dbg):
    """finish(hw=True) uses a hardware breakpoint on the return address and stops there."""
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    dbg.finish(hw=True)
    assert dbg.instruction_pointer == return_address


def test_step_until_address(dbg):
    """
    step_until_address("inner") single steps from outer() until inner() is reached and returns the number of steps.
    """
    dbg.until("outer")
    steps = dbg.step_until_address("inner")
    assert steps > 0
    assert dbg.instruction_pointer == dbg.symbols["inner"]


@ret_gap
def test_step_until_ret(dbg):
    """
    step_until_ret() single steps add() until the next instruction is a return, calling the callback on every step, and
    the return value is 3.
    """
    dbg.until("add")
    seen = []
    steps = dbg.step_until_ret(callback=lambda d: seen.append(d.instruction_pointer), limit=60)
    assert steps == len(seen) - 1
    assert is_return(dbg.next_inst)
    assert dbg.return_value == 3


def test_step_until_condition(dbg):
    """step_until_condition(f) single steps until f(dbg) is true: here until add() has computed 1 + 2."""
    dbg.until("add")
    assert dbg.step_until_condition(lambda d: d.return_value == 3) >= 0
    assert dbg.return_value == 3


def test_step_until_limit(dbg):
    """step_until_condition() gives up after `limit` steps and returns -1 when the condition never holds."""
    dbg.until("main_start")
    assert dbg.step_until_condition(lambda d: False, limit=3) == -1


@next_gaps
@pytest.mark.known_gap("riscv32", RISCV_C_JAL, run=False)
def test_next_until_call(dbg):
    """
    next_until_call() steps (over calls) until the next instruction is a call, the first one after the current position
    in main.
    """
    # The next call after the current instruction: if we are on a call, next() goes over it first (documented)
    calls = calls_in(dbg, "main_start", "after_input")
    expected = calls[1] if calls[0].address == dbg.symbols["main_start"] else calls[0]
    dbg.until("main_start")
    dbg.next_until_call()
    assert dbg.next_inst.is_call
    assert dbg.instruction_pointer == expected.address


def test_jump(dbg):
    """
    jump("main_end") moves the instruction pointer without running the code in between: the program skips the whole body
    of main and prints nothing.
    """
    dbg.until("main_start")
    dbg.jump("main_end")
    assert dbg.instruction_pointer == dbg.symbols["main_end"]
    dbg.c()
    output = dbg.p.recvall(timeout=5)
    assert b"ready" not in output and b"result" not in output


def test_setting_the_instruction_pointer_jumps(dbg):
    """Assigning dbg.instruction_pointer is a jump: the new value is read back."""
    dbg.until("main_start")
    dbg.instruction_pointer = dbg.symbols["main_end"]
    assert dbg.instruction_pointer == dbg.symbols["main_end"]


@pytest.mark.known_gap("new_libdebug", "interrupt() raises NotImplementedError")
@QEMU_BLOCKED_READ
def test_interrupt_a_blocking_read(dbg):
    """
    interrupt() stops a process blocked in read() (inside the libc), and c() then resumes it so that it receives the
    line sent afterwards.
    """
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    dbg.interrupt()
    assert not dbg.running
    if not dbg.exe.statically_linked:
        assert dbg.instruction_pointer not in dbg.exe  # inside read() in the libc
    done = dbg.c(wait=False)
    dbg.p.sendline(b"after interrupt")
    assert done.wait(10)
    assert b"line after interrupt" in dbg.p.recvall(timeout=5)


# BUG: We have a race condition here. If we put a sleep(0.1) after the interrupt it works perfectly fine
@pytest.mark.known_gap("new_libdebug", "interrupt() raises NotImplementedError")
@QEMU_BLOCKED_READ
def test_input_sent_while_interrupted_in_a_read(dbg):
    """
    The typical exploit flow: interrupt the process while it waits for input, send the payload while it is stopped,
    continue, and the program reads that payload.
    """
    # Typical exploit flow: stop the program while it waits for input, inspect, send the payload, continue
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    dbg.interrupt()
    dbg.p.sendline(b"after interrupt")
    dbg.c()
    assert b"line after interrupt" in dbg.p.recvall(timeout=5)


def test_interrupt_a_stopped_process(dbg):
    """interrupt() on a process that is already stopped returns False and leaves the wait priority at 0."""
    assert dbg.interrupt() is False
    assert dbg.priority == 0

# NOTE: This touches a good point that we expect the user to use done.wait() instead of wait(), but it is not clear enough. Let's see how to handle things better
def test_wait_for_a_breakpoint(dbg):
    """c(wait=False) followed by wait() blocks the script until the breakpoint on after_input is hit."""
    dbg.b("after_input")
    dbg.c(wait=False)
    dbg.p.sendline(b"x")
    dbg.wait()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_return_value_can_be_overwritten(dbg):
    """Assigning dbg.return_value after finish() changes what the caller sees: the program prints the fake pid 1234."""
    dbg.until("ask_pid")
    dbg.finish()
    dbg.return_value = 1234
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"pid 1234" in dbg.p.recvall(timeout=5)


@pytest.mark.known_gap("native", "ret() raises 'Not implemented yet'")
@pytest.mark.known_gap("remote", "ret() raises 'Not implemented yet'")
@pytest.mark.known_gap("foreign", "ret() raises 'Not implemented yet'")
def test_ret(dbg):
    """ret(value) leaves the current function at once with the given return value, without running the rest of it."""
    # Leave the current function without running the rest of it, with a chosen return value
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    dbg.ret(1234)
    assert dbg.instruction_pointer == return_address
    assert dbg.return_value == 1234


########################## OPTIONS ##########################

@pytest.mark.known_gap("new_libdebug", "__saved_ip takes new libdebug's backtrace()[-1], the outermost frame, as the return address: finish() waits for an address that never comes", run=False)
def test_finish_without_waiting(dbg):
    """finish(wait=False) returns an event at once; once it is set the process is back in outer() after the call."""
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    done = dbg.finish(wait=False)
    assert done.wait(10)
    assert dbg.instruction_pointer == return_address


@next_gaps
def test_next_over_a_call_with_a_hardware_breakpoint(dbg):
    """next(hw=True) steps over a call with a hardware breakpoint on the return address: same stop as without it."""
    call = call_to(dbg, "outer", "inner")
    dbg.until(call.address)
    dbg.next(hw=True)
    assert dbg.instruction_pointer == after_call(call)
    assert dbg.return_value == 40


@pytest.mark.known_gap("libdebug", "the legacy libdebug doesn't step off an address that has a breakpoint: the forced step stays there (test_step_force fails the same way)", run=False)
@pytest.mark.known_gap("new_libdebug", "leaving an address that has a continuing callback derails new libdebug: the process stops at a wrong address (0x14 after c(), elsewhere after until/finish)")
@pytest.mark.parametrize("action", ["c", "until", "finish"])
def test_force_does_not_run_the_callback_of_the_address_it_leaves(dbg, action):
    """
    c(force=True), until(force=True) and finish(force=True) from inner(), which has a continuing callback, leave it and
    reach the return address in outer() without calling that callback again.
    """
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    hits = []
    dbg.b("inner", callback=lambda d: hits.append(1) or False)
    if action == "c":
        dbg.b(return_address)
        dbg.c(force=True)
    elif action == "until":
        dbg.until(return_address, force=True)
    else:
        dbg.finish(force=True)
    assert dbg.instruction_pointer == return_address
    assert hits == []


def test_step_until_address_gives_up_at_the_limit(dbg):
    """
    step_until_address() calls its callback before every step and returns -1 after `limit` steps if the address is
    still not reached.
    """
    dbg.until("outer")
    seen = []
    assert dbg.step_until_address("main_end", callback=lambda d: seen.append(d.instruction_pointer), limit=3) == -1
    assert len(seen) == 3
    assert len(set(seen)) == 3  # one step between two calls


def test_step_until_call_gives_up_at_the_limit(dbg):
    """
    step_until_call() inside add(), which calls nothing, calls its callback after every step and returns -1 after
    `limit` steps.
    """
    dbg.until("add")
    seen = []
    assert dbg.step_until_call(callback=lambda d: seen.append(d.instruction_pointer), limit=2) == -1
    assert len(seen) == 2


@pytest.mark.known_gap("arm", ARM_IS_CALL, run=False)
def test_next_until_call_gives_up_at_the_limit(dbg):
    """
    next_until_call() inside add(), which calls nothing, calls its callback after every instruction and returns -1
    after `limit` of them.
    """
    dbg.until("add")
    seen = []
    assert dbg.next_until_call(callback=lambda d: seen.append(d.instruction_pointer), limit=2) == -1
    assert len(seen) == 2


@pytest.mark.known_gap("native", "wait() ignores its timeout unless legacy=True: _priority_wait is called without it (gdb_plus.py:wait)")
@pytest.mark.known_gap("remote", "wait() ignores its timeout unless legacy=True: _priority_wait is called without it (gdb_plus.py:wait)")
@pytest.mark.known_gap("foreign", "wait() ignores its timeout unless legacy=True: _priority_wait is called without it (gdb_plus.py:wait)")
def test_wait_with_a_timeout_returns_while_running(dbg):
    """
    wait(timeout=0.5) on a process that waits for input (it won't stop by itself) returns after about half a second,
    with the process still running.
    """
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    start = time.time()
    dbg.wait(timeout=0.5)
    assert time.time() - start < 5
    assert dbg.running


@pytest.mark.known_gap("new_libdebug", "interrupt() raises NotImplementedError")
@pytest.mark.known_gap("gdb", "racy: when step(timeout=) gives up, _step() interrupts while gdb may still be finishing the step, and the next query of the process can block (passed once, hung once)", run=False)
@pytest.mark.known_gap("libdebug", "interrupt() of a process blocked in read() doesn't complete on this target (test_input_sent_while_interrupted_in_a_read fails the same way)", run=False)
@pytest.mark.known_gap("remote", "interrupt() of a process blocked in read() doesn't complete on this target (test_input_sent_while_interrupted_in_a_read fails the same way)", run=False)
@pytest.mark.known_gap("i386", "interrupt() of a process blocked in read() doesn't complete on this target (test_input_sent_while_interrupted_in_a_read fails the same way)", run=False)
@QEMU_BLOCKED_READ
def test_step_into_a_blocking_syscall_gives_up_after_the_timeout(dbg):
    """
    step(timeout=) on the syscall of a read() that waits for input doesn't block forever: after the timeout gdb_plus
    interrupts the process, the step returns, and the program still reads the line sent afterwards.
    """
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    dbg.interrupt()  # in read(), on the instruction after the syscall: the kernel restarts it on the next step
    start = time.time()
    dbg.step(timeout=1)
    assert time.time() - start < 8
    assert not dbg.running
    dbg.p.sendline(b"after the step")
    dbg.c()
    assert b"line after the step" in dbg.p.recvall(timeout=5)
