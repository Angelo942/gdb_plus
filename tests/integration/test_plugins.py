"""
The shortcuts to GEF and pwndbg commands (bins, chunks, context, telescope) and the detection of the plugin.
The suite runs with a vanilla gdb by default: these tests load the plugin for their own debugger only
(plugin_script), or use the one of --gdb-flavor=gef|pwndbg.
"""
import pytest

PLUGINS = [pytest.param("gef", marks=pytest.mark.gef), pytest.param("pwndbg", marks=pytest.mark.pwndbg)]

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.not_applicable("libdebugs", "GEF and pwndbg are gdb plugins"),
    pytest.mark.untested("gdbserver", "the shortcuts only forward a command to the plugin: covered on a local process"),
    pytest.mark.untested("foreign", "the shortcuts only forward a command to the plugin: covered on x86-64"),
]


@pytest.fixture
def plugged(debugger, basic, plugin_script):
    def start(plugin):
        dbg = debugger(basic, script=plugin_script(plugin))
        done = dbg.until("after_input", wait=False)
        dbg.p.sendline(b"x")
        assert done.wait(30)  # malloc ran: there is a heap to show
        return dbg
    return start


@pytest.mark.parametrize("plugin", PLUGINS)
def test_plugin_is_detected(plugged, plugin):
    """With GEF or pwndbg loaded in gdb, gdb_plus detects which one it is (dbg._gef / dbg._pwndbg)."""
    dbg = plugged(plugin)
    assert (dbg._gef, dbg._pwndbg) == (plugin == "gef", plugin == "pwndbg")


@pytest.mark.parametrize("plugin", PLUGINS)
def test_telescope(plugged, plugin, capfd):
    """telescope() forwards to the plugin's telescope command, which prints the stack starting at the stack pointer."""
    dbg = plugged(plugin)
    capfd.readouterr()
    dbg.telescope(dbg.stack_pointer, 4)
    output = capfd.readouterr().out
    assert hex(dbg.stack_pointer)[2:] in output.lower()


@pytest.mark.parametrize("plugin", PLUGINS)
@pytest.mark.parametrize("command", ["bins", "chunks"])
def test_heap_commands(plugged, plugin, command, capfd):
    """bins() and chunks() forward to the plugin's heap commands (after malloc ran) and leave the process stopped."""
    dbg = plugged(plugin)
    capfd.readouterr()
    getattr(dbg, command)()
    output = capfd.readouterr().out
    assert output.strip() and "not detected" not in output
    assert not dbg.running  # it was stopped before: it must stay stopped


@pytest.mark.parametrize("plugin", PLUGINS)
def test_context(plugged, plugin, capfd):
    """context() prints the plugin's context view, which names the current location (after_input)."""
    dbg = plugged(plugin)
    capfd.readouterr()
    dbg.context()
    assert "after_input" in capfd.readouterr().out


def test_shortcuts_without_a_plugin(debugger, basic, capfd, _gdb_environment):
    """
    Without a plugin the shortcuts don't fail: telescope(), bins() and chunks() print that GEF or pwndbg is needed.
    """
    if _gdb_environment != "vanilla":
        pytest.skip(f"the suite runs with --gdb-flavor={_gdb_environment}")
    dbg = debugger(basic)
    assert not dbg._gef and not dbg._pwndbg
    capfd.readouterr()
    dbg.telescope()
    dbg.bins()
    dbg.chunks()
    output = capfd.readouterr().out
    assert "telescope requires GEF or pwndbg" in output
    assert output.count("GEF or pwndbg not detected") == 2
