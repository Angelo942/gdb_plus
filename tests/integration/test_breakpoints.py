"""Breakpoints and callbacks: return values, ordering, nesting and deletion."""
from queue import Queue

import pytest

from support.targets import read_c_long


@pytest.fixture
def dbg(debugger, basic, backend):
    return debugger(basic, aslr=False, backend=backend)


@pytest.mark.parametrize("location", ["symbol", "symbol+offset", "offset", "absolute"])
def test_locations(dbg, location):
    """
    b() accepts every form of address: a symbol, "symbol+offset", a PIE-relative integer and an absolute address. Breaks
    on the second instruction of many_args and checks that c() stops exactly there.
    """
    if location == "offset" and not dbg.exe.pie:
        pytest.skip("not applicable: an integer is an offset only in a PIE, in the others it is the address")
    # The second instruction: +4 could fall inside an instruction (x86, compressed riscv)
    target = list(dbg.disassemble(dbg.symbols["many_args"], 0x20))[1].address
    offset = target - dbg.symbols["many_args"]
    value = {"symbol": "many_args", "symbol+offset": f"many_args+{offset:#x}", "offset": target - dbg.exe.address, "absolute": target}[location]
    if location == "symbol":
        target -= offset
    dbg.b(value)
    dbg.c()
    assert dbg.instruction_pointer == target


def test_breakpoint_is_registered(dbg):
    """
    b("add") returns a Breakpoint object, stores it in dbg.breakpoints under the resolved address and marks it user
    defined and not temporary.
    """
    breakpoint = dbg.b("add")
    assert dbg.control.breakpoints[dbg.symbols["add"]] == [breakpoint]
    assert breakpoint.user_defined and not breakpoint.temporary


def test_callback_returning_false_continues(dbg):
    """
    A callback that returns False does not stop the process: the callback on tick() runs once per call (it sees counter
    0..4) and the script only wakes up at the next stopping breakpoint, after_input.
    """
    hits = []
    dbg.b("tick", callback=lambda d: hits.append(read_c_long(d, "counter")) or False)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert hits == [0, 1, 2, 3, 4]
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


@pytest.mark.parametrize("returned", [None, True])
def test_callback_returning_none_or_true_stops(dbg, returned):
    """
    A callback that returns None or True stops the process like a plain breakpoint: c() returns with the instruction
    pointer on tick().
    """
    dbg.b("tick", callback=lambda d: returned)
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]


def test_callbacks_on_the_same_address_run_last_in_first_out(dbg):
    """
    Two continuing callbacks on the same address both run, the most recent one first (LIFO), and the process keeps going
    to the next breakpoint.
    """
    order = []
    dbg.b("add", callback=lambda d: order.append("first") or False)
    dbg.b("add", callback=lambda d: order.append("second") or False)
    dbg.b("many_args")
    dbg.c()
    assert order == ["second", "first"]
    assert dbg.instruction_pointer == dbg.symbols["many_args"]


def test_one_stopping_callback_is_enough(dbg):
    """
    With a continuing and a stopping callback on the same address, the process stops: one callback that asks to stop
    wins.
    """
    dbg.b("add", callback=lambda d: False)
    dbg.b("add", callback=lambda d: True)
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["add"]


def test_temporary_breakpoint(dbg):
    """tb() stops once and is then removed from dbg.breakpoints: the five calls to tick() stop only the first time."""
    dbg.tb("tick")
    dbg.b("after_input")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]
    assert dbg.control.breakpoints[dbg.symbols["tick"]] == []
    dbg.p.sendline(b"x")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_hardware_breakpoint(dbg):
    """b(..., hw=True) sets a hardware breakpoint (Breakpoint.hw) that stops the process like a software one."""
    breakpoint = dbg.b("many_args", hw=True)
    assert breakpoint.hw
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["many_args"]


@pytest.mark.known_gap("riscv32", "Arguments has no stack lookup for riscv and mips")
@pytest.mark.known_gap("riscv64", "Arguments has no stack lookup for riscv and mips")
@pytest.mark.known_gap("mips", "Arguments has no stack lookup for riscv and mips")
@pytest.mark.known_gap("mips64", "Arguments has no stack lookup for riscv and mips")
def test_callback_reads_arguments(dbg):
    """
    Inside a callback dbg.args reads the arguments of the current function: many_args(0, 1, ..., 9) gives the ten
    values, including the ones passed on the stack.
    """
    arguments = Queue()
    dbg.b("many_args", callback=lambda d: arguments.put(d.args[0:10]) or False)
    dbg.b("outer")
    dbg.c()
    assert arguments.get(timeout=1) == list(range(10))


def test_callback_writes_arguments(dbg):
    """
    A callback can change an argument before the function runs: setting the second argument of add(1, 2) to 100 changes
    the result printed by the program to 472.
    """
    def double(d):
        d.args[1] = 100
        return False
    dbg.b("add", callback=double)
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"result 472" in dbg.p.recvall(timeout=5)


def test_callback_can_finish(dbg):
    """
    finish() can be called inside a callback: it returns inner()'s return value (40) and does not wake up the c() of the
    script, which still stops on the next breakpoint (tick). Checks the priority of MyEvent.
    """
    # The finish() inside the callback must not wake the c() of the script
    results = []

    def callback(d):
        d.finish()
        results.append(d.return_value)
        return False
    dbg.b("inner", callback=callback)
    dbg.b("tick")
    dbg.c()
    assert results == [40]
    assert dbg.instruction_pointer == dbg.symbols["tick"]


def test_callback_can_step_and_stop(dbg):
    """
    step() inside a callback moves the process by one instruction and the callback can then stop: c() returns one
    instruction after the start of add().
    """
    dbg.b("add", callback=lambda d: d.step() and True)
    dbg.c()
    first = next(dbg.disassemble(dbg.symbols["add"], 0x10))
    assert dbg.instruction_pointer == dbg.symbols["add"] + first.size


def test_callback_can_set_breakpoints(dbg):
    """
    A callback can set a new breakpoint (a temporary one on tick) while the process is stopped in it, and its own
    temporary breakpoint on outer is removed.
    """
    def callback(d):
        d.b("tick", temporary=True)
        return False
    dbg.b("outer", callback=callback, temporary=True)
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]
    assert dbg.control.breakpoints[dbg.symbols["outer"]] == []


def test_stepping_onto_a_continuing_callback_still_stops(dbg):
    """
    si() onto an address that has a continuing callback runs the callback once and still stops after the single step:
    stepping is not turned into a continue.
    """
    dbg.until("add")
    following = dbg.instruction_pointer + dbg.next_inst.size
    hits = []
    dbg.b(following, callback=lambda d: hits.append(1) or False)
    dbg.si()
    assert dbg.instruction_pointer == following
    assert hits == [1]


def test_every_instruction(dbg):
    """
    Breakpoints on four consecutive instructions are all hit, one per c(): stepping over the current breakpoint to
    resume must not skip the next one.
    """
    # Breakpoints on consecutive instructions must not be skipped
    dbg.until("add")
    instructions = list(dbg.disassemble(dbg.symbols["add"] + dbg.next_inst.size, 0x10))[:4]
    for instruction in instructions:
        dbg.b(instruction.address)
    for instruction in instructions:
        dbg.c()
        assert dbg.instruction_pointer == instruction.address


def test_continuing_callbacks_on_every_instruction(dbg):
    """
    Continuing callbacks on four consecutive instructions all run, in order, while the process continues to many_args.
    """
    dbg.until("add")
    instructions = list(dbg.disassemble(dbg.symbols["add"] + dbg.next_inst.size, 0x10))[:4]
    seen = []
    for instruction in instructions:
        dbg.b(instruction.address, callback=lambda d: seen.append(d.instruction_pointer) or False)
    dbg.until("many_args")
    assert seen == [instruction.address for instruction in instructions]


def test_delete_by_address(dbg):
    """
    delete_breakpoint("tick") removes the only breakpoint at that address: the process runs straight to after_input.
    """
    dbg.b("tick")
    dbg.delete_breakpoint("tick")
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_delete_by_object(dbg):
    """
    delete_breakpoint(breakpoint) removes that one Breakpoint and keeps the others at the same address (here a
    continuing callback).
    """
    first = dbg.b("tick")
    dbg.b("tick", callback=lambda d: False)
    dbg.delete_breakpoint(first)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_delete_ambiguous_or_missing(dbg):
    """
    delete_breakpoint() by address raises when no breakpoint is there, and when two are there (it can't know which one
    to remove).
    """
    with pytest.raises(Exception):
        dbg.delete_breakpoint("tick")
    dbg.b("tick")
    dbg.b("tick")
    with pytest.raises(Exception):
        dbg.delete_breakpoint("tick")


def test_legacy_callback(dbg):
    """
    legacy_callback= still works: with gdb it runs inside gdb.Breakpoint.stop(), with libdebug as a normal callback. It
    must run once per call of tick (5 times).
    """
    # gdb runs it inside gdb.Breakpoint.stop(), the libdebug backends as a normal callback
    hits = []
    dbg.b("tick", legacy_callback=lambda d: hits.append(1) or False)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert len(hits) == 5


@pytest.mark.known_gap("libdebug", "the legacy fork is started with multithread=False: the run hangs", run=False)
@pytest.mark.untested("qemu", "the freestanding fixtures of the QEMU targets have no pthreads")
def test_breakpoints_in_threads(debugger, target_binary, backend):
    """
    A breakpoint in a function run by four threads (the threads fixture) is hit by every thread, and the callback sees
    each thread's argument (0..3).
    """
    dbg = debugger(target_binary("threads"), backend=backend)
    hits = Queue()
    dbg.b("thread_marker", callback=lambda d: hits.put(d.args[0]) or False)
    dbg.c()
    assert b"done 4" in dbg.p.recvall(timeout=5)
    assert sorted(hits.get(timeout=1) for _ in range(4)) == [0, 1, 2, 3]


########################## MORE OPTIONS ##########################

def test_temporary_breakpoint_with_a_continuing_callback(dbg):
    """
    tb(callback=) whose callback returns False runs the callback once, on the first of the five calls to tick(), never
    stops there, and is gone afterwards.
    """
    hits = []
    dbg.tb("tick", callback=lambda d: hits.append(read_c_long(d, "counter")) or False)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert hits == [0]
    assert dbg.instruction_pointer == dbg.symbols["after_input"]
    assert dbg.control.breakpoints[dbg.symbols["tick"]] == []


def test_temporary_hardware_breakpoint(dbg):
    """tb(hw=True) is a hardware breakpoint that stops only on the first call to tick()."""
    breakpoint = dbg.tb("tick", hw=True)
    assert breakpoint.hw and breakpoint.temporary
    dbg.b("after_input")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]
    dbg.p.sendline(b"x")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["after_input"]
    assert read_c_long(dbg, "counter") == 5


def test_breakpoint_set_again_after_its_deletion(dbg):
    """
    A breakpoint deleted and then set again on the same address stops the process (new libdebug only disables deleted
    breakpoints: b() must enable it again).
    """
    dbg.b("tick")
    dbg.delete_breakpoint("tick")
    dbg.b("tick")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]


@pytest.mark.known_gap("libdebugs", "delete_breakpoint() deletes (libdebug) or disables (new libdebug) the native breakpoint of the address, which the other Breakpoint on that address relies on too")
def test_delete_by_address_leaves_the_internal_breakpoints(dbg):
    """
    delete_breakpoint(address) only considers the breakpoints of the user: an internal one (user_defined=False) on the
    same address stays and still stops the process.
    """
    internal = dbg.b("tick", user_defined=False)
    dbg.b("tick")
    dbg.delete_breakpoint("tick")
    assert dbg.control.breakpoints[dbg.symbols["tick"]] == [internal]
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]
