"""ExceptionalChecking: a check implemented with int3 + SIGUSR1 handlers that rewrite the code."""
import pytest

HANDLER_RET = 0x04011ff
CHECK_CALL = 0x0401341

BACKENDS = ["gdb", pytest.param("libdebug", marks=pytest.mark.libdebug)]


@pytest.fixture
def dbg(debugger, challenge):
    def start(backend):
        dbg = debugger(challenge("ExceptionalChecking_patched"), backend=backend)
        dbg.p.sendline(b"serial_a_caso")
        dbg.until(CHECK_CALL)
        dbg.step()
        return dbg
    return start


def _trace(dbg, handler, limit):
    output = []
    state = {"signal": False}

    def callback(d):
        if state["signal"]:
            d.signal("SIGUSR1", handler=handler) if handler else d.signal("SIGUSR1")
            state["signal"] = False
        instruction = d.next_inst
        if instruction.mnemonic == "int3":
            state["signal"] = True
            d.write(d.instruction_pointer, b"\x90")
        else:
            output.append(instruction.toString())
    return dbg.step_until_ret(callback, limit=limit), output


@pytest.mark.parametrize("backend", BACKENDS)
def test_follow_the_signal_handlers(dbg, reference_file, backend):
    """
    Single steps a serial check that hides its logic in int3 + SIGUSR1 handlers: each int3 is replaced by a nop and the
    signal delivered by hand; the instructions seen must match the legacy dump.
    """
    debugger = dbg(backend)
    steps, output = _trace(debugger, HANDLER_RET, limit=5 if backend == "gdb" else 50)
    if backend == "gdb":
        assert steps == -1
    assert reference_file("dump_ExceptionalChecking").startswith("\n".join(output))


@pytest.mark.libdebug
def test_hardware_breakpoint_after_the_handler(dbg, reference_file):
    """
    Same trace with the legacy libdebug and no handler address: stepping out of the signal handler must still follow the
    code of the dump.
    """
    debugger = dbg("libdebug")
    _, output = _trace(debugger, None, limit=50)
    assert reference_file("dump_ExceptionalChecking").startswith("\n".join(output))


@pytest.mark.parametrize("backend", BACKENDS)
def test_step_into_a_signal(dbg, backend):
    """
    signal("SIGUSR1", step=True) stops on the first instruction of the program's handler (0x401196), with gdb and after
    migrating to libdebug.
    """
    debugger = dbg("gdb")
    debugger.si(repeat=2)
    if backend == "libdebug":
        debugger.migrate(libdebug=True)
    debugger.signal("SIGUSR1", step=True)
    assert debugger.instruction_pointer == 0x401196
