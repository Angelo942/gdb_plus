"""
Shared configuration of the gdb_plus test suite. See tests/README.md.

Tiers (one directory each, selected automatically by path):
    unit/         no gdb, no process, milliseconds
    integration/  one feature per test on the purpose-built binaries of fixtures/src
    regression/   the CTF challenges of the legacy suite, replayed end to end
"""
import atexit
import faulthandler
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
# Always test the checkout, never an installed copy of gdb_plus
sys.path.insert(0, str(REPO))
sys.path.insert(1, str(TESTS))

from support import environment  # noqa: E402

# Saves every result in tests/.results/ for the dashboard (python3 tests/dashboard/server.py);
# --affected runs only the tests that reach the changed code (support/affected.py);
# -n N hands out the slowest tests first (support/schedule.py)
pytest_plugins = ["support.results", "support.affected", "support.schedule"]

# The legacy suite lives next to us until it is deleted. Don't collect it (test_performances runs at import).
collect_ignore = ["test.py", "test_old.py", "test_Structure.py", "test_new_libdebug.py", "test_performances.py"]
collect_ignore_glob = ["docker_image_*", "*_folder", "fixtures"]

TIER_TIMEOUTS = {"unit": 10, "integration": 10, "regression": 180}
TIERS = list(TIER_TIMEOUTS)
WATCHDOG_LOG = TESTS / f".watchdog-{os.getpid()}.txt"  # one per run: parallel runs must not clobber it


def pytest_addoption(parser):
    group = parser.getgroup("gdb_plus")
    group.addoption("--gdb-flavor", default=os.environ.get("GDB_PLUS_GDB_FLAVOR", "vanilla"),
                    choices=["vanilla", "gef", "pwndbg", "user"],
                    help="gdb extension loaded by every debugger. 'user' keeps your own ~/.gdbinit. "
                         "Default: vanilla (env GDB_PLUS_GDB_FLAVOR)")
    group.addoption("--show-gdb", action="store_true",
                    help="open gdb in a real terminal (context.terminal) instead of the headless one")
    group.addoption("--run-network", action="store_true",
                    help="run the tests that connect to live CTF servers")
    group.addoption("--timeout-scale", type=float, default=float(os.environ.get("GDB_PLUS_TIMEOUT_SCALE", 1)),
                    help="multiply every timeout (slow machines, docker, valgrind...)")
    group.addoption("--pwn-log-level", default="error", help="pwntools log level during the tests")
    group.addoption("--remote-gdbserver", metavar="USER@HOST", default=os.environ.get("GDB_PLUS_REMOTE_GDBSERVER"),
                    help="arm64 machine reached with ssh (key login) for the aarch64_remote target: the fixtures are "
                         "built and run there under gdbserver (env GDB_PLUS_REMOTE_GDBSERVER)")


########################## SELECTION ##########################

def _tier(item):
    parts = Path(str(item.fspath)).relative_to(TESTS).parts
    return parts[0] if parts and parts[0] in TIERS else None


def _skip_reason(item, config):
    tier = _tier(item)
    if tier in ["integration", "regression"] and not environment.has_gdb():
        return "gdb and gdbserver are required"
    if item.get_closest_marker("network") and not config.getoption("--run-network"):
        return "talks to a live server: use --run-network"
    if item.get_closest_marker("sage") and not environment.has_sage():
        return "SageMath is not installed"
    if item.get_closest_marker("libclang") and not environment.has_libclang():
        return "libclang is not available"
    for marker in item.iter_markers("qemu"):
        arch = marker.args[0]
        if not environment.has_qemu(arch):
            return f"qemu-user for {arch} and gdb-multiarch are required"
        if item.get_closest_marker("syscall_catchpoints") and not environment.qemu_catches_syscalls(arch):
            return f"this qemu-{arch} doesn't report syscalls to gdb (catch syscall: 'Your system does not support this type of catchpoint')"
    if item.get_closest_marker("remote_gdbserver") and shutil.which("gdb-multiarch") is None:
        return "gdb-multiarch is required to debug the arm64 gdbserver of --remote-gdbserver"
    if item.get_closest_marker("libdebug") and not environment.has_legacy_libdebug():
        return "legacy libdebug: pip3 install git+https://github.com/Angelo942/libdebug.git"
    if item.get_closest_marker("new_libdebug") and not environment.has_new_libdebug():
        return "libdebug >= 0.8 is not installed"
    for plugin, path in [("gef", environment.gef_path), ("pwndbg", environment.pwndbg_path)]:
        if item.get_closest_marker(plugin):
            if path() is None:
                return f"{plugin} not found (set GDB_PLUS_{plugin.upper()})"
            flavor = config.getoption("--gdb-flavor")
            if flavor not in ["vanilla", plugin]:
                return f"needs {plugin}, but the suite runs with --gdb-flavor={flavor}"
    return None


def _declared_outcome(item):
    """
    The not_applicable / untested / known_gap marker that matches the target of a run parametrized over the
    target axis (support/results.py). Declarations on a test that doesn't run on that domain are only recorded.
    """
    from support.results import declarations, domain_of
    domain, parameter = domain_of(item)
    if parameter is None:
        return None
    for declared, status, reason, options in declarations(item, options=True):
        if declared == domain:
            if status == "not_applicable":
                return pytest.mark.skip(reason=f"not applicable: {reason}")
            if status == "not_covered":
                return pytest.mark.skip(reason=f"not covered: {reason}")
            return pytest.mark.xfail(strict=True, reason=f"{domain}: {reason}", run=options.get("run", True))
    return None


def pytest_collection_modifyitems(config, items):
    # Without the arm64 machine its runs are deselected, not skipped: the recorder keeps the results of the last run
    # that had it instead of replacing them with "not run"
    if not config.getoption("--remote-gdbserver"):
        remote = [item for item in items if item.get_closest_marker("remote_gdbserver")]
        if remote:
            items[:] = [item for item in items if not item.get_closest_marker("remote_gdbserver")]
            config.hook.pytest_deselected(items=remote)
    for item in items:
        tier = _tier(item)
        if tier is not None:
            item.add_marker(getattr(pytest.mark, tier))
        # A declaration is about the design, not about this machine: it wins over a missing tool
        declared = _declared_outcome(item)
        if declared is not None and declared.name == "skip":
            item.add_marker(declared)
            continue
        # Target parametrization adds the libdebug / qemu markers by itself (see integration/conftest.py)
        reason = _skip_reason(item, config)
        if reason is not None:
            item.add_marker(pytest.mark.skip(reason=reason))
        elif declared is not None:
            item.add_marker(declared)


########################## TIMEOUTS ##########################

class TestTimeout(Exception):
    pass


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    # Same trick as timeout_decorator in the legacy suite: SIGALRM interrupts the main thread
    # even while it is blocked waiting for a debugger event.
    if item.config.pluginmanager.hasplugin("timeout"):
        yield
        return
    marker = item.get_closest_marker("timeout")
    seconds = marker.args[0] if marker else TIER_TIMEOUTS.get(_tier(item), 60)
    seconds = max(1, int(seconds * item.config.getoption("--timeout-scale")))

    def expired(signum, frame):
        raise TestTimeout(f"test did not finish in {seconds}s")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


# The watchdog of the running test (deadline and log). faulthandler has a single timer per process: one test at a time.
_watchdog = {}


def _arm_watchdog():
    remaining = max(1, _watchdog["deadline"] - time.monotonic())
    faulthandler.dump_traceback_later(remaining, exit=True, file=_watchdog["stream"])


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    # SIGALRM can't interrupt a main thread stuck inside C code (libdebug's waitpid...). Last resort: if the
    # whole test (setup, call, teardown) takes far longer than its timeout, dump every thread and stop the run.
    marker = item.get_closest_marker("timeout")
    seconds = marker.args[0] if marker else TIER_TIMEOUTS.get(_tier(item), 60)
    hard_limit = seconds * item.config.getoption("--timeout-scale") * 2 + 60
    # Not stderr: pytest captures it and the buffered report is lost when faulthandler calls _exit()
    with open(WATCHDOG_LOG, "w") as log:
        log.write(f"{item.nodeid} took more than {hard_limit:.0f}s. The run was stopped. Threads:\n\n")
    _watchdog.update(deadline=time.monotonic() + hard_limit, stream=open(WATCHDOG_LOG, "a"))
    _arm_watchdog()
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()
        _watchdog["stream"].close()
        _watchdog.clear()
        WATCHDOG_LOG.unlink(missing_ok=True)


@pytest.hookimpl(trylast=True)
def pytest_exception_interact(node, call, report):
    # pytest's faulthandler plugin cancels the timer whenever a test fails (it is meant for --pdb): arm it again,
    # or a teardown that hangs after a failure is never stopped. Not under --pdb, where someone is debugging.
    if _watchdog and not node.config.getoption("usepdb"):
        _arm_watchdog()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"report_{report.when}", report)
    # Callbacks run inside gdb's python can only print in gdb's terminal. Show it when a test fails.
    log = getattr(item, "gdb_terminal_log", None)
    if report.failed and log is not None and log.exists():
        text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", log.read_bytes()[-6000:]).decode(errors="replace")
        report.sections.append(("gdb terminal (tail)", text))


########################## ENVIRONMENT ##########################

def _write_gdbinit(directory: Path, flavor: str):
    lines = ["set pagination off", "set history save off"]
    # The API bridge of pwntools needs rpyc inside gdb's python. The docker images add it from ~/.gdbinit,
    # which we are replacing, so add the site-packages of the interpreter running the tests (at the end of sys.path).
    try:
        import rpyc
        site = Path(rpyc.__file__).resolve().parent.parent
        lines += ["python", f"import sys; sys.path.append({str(site)!r})", "end"]
    except ImportError:
        pass
    if flavor == "gef":
        lines.append(f"source {environment.gef_path()}")
    elif flavor == "pwndbg":
        lines.append(f"source {environment.pwndbg_path()}")
    (directory / "gdb").mkdir(parents=True, exist_ok=True)
    (directory / "gdb" / "gdbinit").write_text("\n".join(lines) + "\n")


@pytest.fixture(scope="session", autouse=True)
def _gdb_environment(request, tmp_path_factory):
    from pwn import context
    config = request.config
    flavor = config.getoption("--gdb-flavor")
    saved = {name: os.environ.get(name) for name in ["XDG_CONFIG_HOME", "TERM"]}
    if flavor != "user":
        if flavor == "gef" and environment.gef_path() is None:
            pytest.exit("--gdb-flavor=gef but GEF was not found (set GDB_PLUS_GEF)")
        if flavor == "pwndbg" and environment.pwndbg_path() is None:
            pytest.exit("--gdb-flavor=pwndbg but pwndbg was not found (set GDB_PLUS_PWNDBG)")
        # gdb >= 11 reads $XDG_CONFIG_HOME/gdb/gdbinit instead of ~/.gdbinit
        xdg = tmp_path_factory.mktemp("xdg")
        _write_gdbinit(xdg, flavor)
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
    if not os.environ.get("TERM") or os.environ["TERM"] == "dumb":
        os.environ["TERM"] = "xterm"
    if not config.getoption("--show-gdb"):
        context.terminal = [sys.executable, str(TESTS / "support" / "headless_terminal.py")]
    yield flavor
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


@pytest.fixture(autouse=True)
def _isolation(request, monkeypatch, tmp_path):
    """Each test gets its own pwntools context and args. Debugging tests also run in their own directory."""
    from pwn import context, args
    if _tier(request.node) in ["integration", "regression"]:
        monkeypatch.chdir(tmp_path)
        log = tmp_path / "gdb-terminal.log"
        monkeypatch.setenv("GDB_PLUS_TERMINAL_LOG", str(log))
        request.node.gdb_terminal_log = log
    switches = ["REMOTE", "NOPTRACE", "ASLR"]
    saved = {name: args[name] for name in switches if name in args}
    def clear():
        for name in switches:
            args.pop(name, None)
            vars(args).pop(name, None)  # `args.REMOTE = "1"` sets an attribute, not a key

    clear()
    try:
        with context.local(log_level=request.config.getoption("--pwn-log-level")):
            yield
    finally:
        clear()
        args.update(saved)


########################## BINARIES ##########################

@pytest.fixture(scope="session")
def _built_fixtures():
    return environment.build_fixtures()


@pytest.fixture(scope="session")
def remote_host(request, tmp_path_factory):
    """
    The arm64 machine of --remote-gdbserver (support/remote_host.py), checked and with the fixture sources copied
    there once per session. Skips the tests that use it when it can't be reached or isn't arm64.
    """
    from support.remote_host import RemoteHost
    destination = request.config.getoption("--remote-gdbserver")
    if not destination:
        pytest.skip("needs an arm64 machine with gdbserver: --remote-gdbserver=user@host")
    host = RemoteHost(destination, tmp_path_factory.mktemp("remote_fixtures"))
    try:
        host.setup()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        pytest.skip(f"--remote-gdbserver={destination} can't be used: {error}")
    if host.arch != "aarch64":
        pytest.skip(f"the aarch64_remote target needs an arm64 machine, {destination} is {host.arch}")
    return host

@pytest.fixture
def fixture_binary(_built_fixtures, tmp_path):
    """
    fixture_binary("basic") -> path of a copy of tests/fixtures/bin/basic (built from fixtures/src) in the
    test's directory. Copying also keeps spaces out of the path: gdbserver's --wrapper (used by pwntools
    when env= is given) splits it.
    """
    def get(name: str) -> str:
        if name not in _built_fixtures:
            if name.endswith("_i386"):
                hint = "gcc-multilib"
            elif name.rsplit("_", 1)[-1] in environment.QEMU_BINARIES:
                hint = "clang and lld for the freestanding cross build"
            else:
                hint = "gcc and make"
            pytest.skip(f"could not build fixture {name} (needs {hint})")
        destination = tmp_path / name
        if not destination.exists():
            shutil.copy(environment.FIXTURES / "bin" / name, destination)
        return str(destination)
    return get


@pytest.fixture
def ctf_binary(tmp_path):
    """
    ctf_binary("cube") -> path of a copy of tests/cube in the test's directory, made executable.
    Extra files can be copied next to it (ctf_binary("risky-business", extra=["flag.txt"])).
    """
    def get(name: str, *, extra=()) -> str:
        source = TESTS / name
        if not source.exists():
            pytest.skip(f"missing challenge binary tests/{name}")
        destination = tmp_path / Path(name).name
        shutil.copy(source, destination)
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        for file in extra:
            shutil.copy(TESTS / file, tmp_path / Path(file).name)
        return str(destination)
    return get


@pytest.fixture
def reference_file():
    """Expected outputs stored next to the challenges (dump_Cube, ...)."""
    def get(name: str) -> str:
        return (TESTS / name).read_text()
    return get


########################## DEBUGGERS ##########################

@pytest.fixture
def plugin_script(_gdb_environment):
    """gdbscript that loads GEF or pwndbg for a single debugger (empty if the whole suite already uses it)."""
    def get(plugin: str) -> str:
        if _gdb_environment == plugin:
            return ""
        path = environment.gef_path() if plugin == "gef" else environment.pwndbg_path()
        if path is None or _gdb_environment not in ["vanilla"]:
            pytest.skip(f"needs {plugin}")
        return f"source {path}\n"
    return get


def _process_alive(pid):
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError, TypeError):
        return False
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except OSError:
        return False


def _kill(pids):
    for pid in pids:
        if _process_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def _descendants(pid):
    """Every process below pid, read from /proc/<pid>/task/*/children."""
    found, todo = [], [pid]
    while todo:
        for task in Path(f"/proc/{todo.pop()}/task").glob("*"):
            try:
                children = [int(child) for child in (task / "children").read_text().split()]
            except OSError:
                continue
            found += children
            todo += children
    return found


def _shutdown(dbg, *, seconds=20, local=True):
    """
    Close a debugger without ever hanging the suite, then kill whatever survived. local=False for a process of another
    machine: its pid means nothing here.
    """
    from pwn import context
    debuggers = [dbg] + list(getattr(dbg, "children", {}).values())
    pids = [d.pid for d in debuggers if getattr(d, "pid", None)] if local else []

    def expired(signum, frame):
        raise TestTimeout("close() hung")

    # SIGALRM only interrupts Python code: a close() blocked in C (on a lock, in a read) never sees it.
    # Killing the processes from another thread closes the pipes and sockets such a close() waits on.
    killer = threading.Timer(seconds, _kill, args=(pids,))
    killer.daemon = True
    previous = signal.signal(signal.SIGALRM, expired)
    killer.start()
    signal.alarm(seconds + 5)
    try:
        with context.silent:
            for d in debuggers:
                try:
                    d.close()
                except Exception:
                    pass
    except TestTimeout:
        pass
    finally:
        killer.cancel()
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    _kill(pids)


def _kill_terminals_of(log):
    """SIGTERM the headless terminals (and so the gdb) started by one test: they inherited its log path."""
    marker = f"GDB_PLUS_TERMINAL_LOG={log}".encode()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if b"headless_terminal.py" in (proc / "cmdline").read_bytes() and marker in (proc / "environ").read_bytes().split(b"\x00"):
                os.kill(int(proc.name), signal.SIGTERM)
        except OSError:
            continue


def _start_gdbserver(target, *, env=None):
    """
    gdbserver for a local program, as a pwntools tube: the program's stdin and stdout are the tube's,
    gdbserver's own messages (stderr) stay out of it. Returns (tube, (host, port)).
    """
    from pwn import context, process
    from support.local_server import free_port
    argv = [target] if isinstance(target, str) else list(target)
    port = free_port()
    with context.local(log_level="error"):
        server = process(["gdbserver", f"127.0.0.1:{port}", *argv], env=env, stderr=subprocess.PIPE)
    listening = threading.Event()

    # Don't probe the port: gdbserver would take the probe for the debugger
    # Read a copy of the pipe with os.read: a thread blocked in stream.readline() holds the lock of the stream and
    # process.close() would wait for it as long as anything keeps the pipe open (the inferior inherits it).
    def watch(fd):
        seen = b""
        try:
            while chunk := os.read(fd, 0x1000):
                seen = (seen + chunk)[-0x100:]
                if b"Listening on port" in seen:
                    listening.set()
        finally:
            os.close(fd)

    threading.Thread(target=watch, args=(os.dup(server.proc.stderr.fileno()),), name="gdbserver_stderr", daemon=True).start()
    if not listening.wait(10):
        _stop_gdbserver(server)
        raise RuntimeError("gdbserver did not start")
    return server, ("127.0.0.1", port)


def _stop_gdbserver(server):
    """Kill gdbserver's inferior before gdbserver: a detached or orphaned inferior would outlive it."""
    _kill(_descendants(server.pid))
    server.close()


@pytest.fixture
def debugger(request):
    """
    Factory: debugger(target, backend="gdb", **Debugger_kwargs) -> Debugger

    backend is a target of the integration axis (integration/conftest.py): gdb, libdebug, new_libdebug,
    remote (the target runs under gdbserver and dbg.p is gdbserver's stdin/stdout), i386 or a qemu arch
    (the target is the binary of that arch: use the `basic` / target_binary fixtures). aarch64_remote is remote on
    the machine of --remote-gdbserver: target is the local copy of a fixture built there (target_binary), which runs
    there under gdbserver.

    Every debugger is closed after the test, even if it fails or hangs. If the test passed we also
    check the invariant every legacy test asserted by hand: the wait priority is back to 0 (the actions interrupt()
    suspended excepted).
    Opt out with @pytest.mark.allow_priority_leak.
    """
    from gdb_plus import Debugger
    from pwn import context
    from support.results import BACKENDS
    created = []
    remote_servers = []  # gdbservers of --remote-gdbserver, stopped after their debugger is closed

    def build(target, **kwargs):
        # A Debugger whose __init__ raises is never returned to us, but its gdb may already hold the process
        # (a qemu gdbstub then never lets the guest exit). Build it in two steps to still be able to close it.
        dbg = Debugger.__new__(Debugger)
        try:
            dbg.__init__(target, **kwargs)
        except BaseException:
            try:
                _shutdown(dbg)
            except Exception:  # half initialized: even reading an attribute may fail through __getattr__
                pass
            raise
        return dbg

    def factory(target, *, backend="gdb", **kwargs):
        if isinstance(target, Path):
            target = str(target)
        if backend not in BACKENDS and backend != "aarch64_remote":
            raise ValueError(backend)
        if backend == "aarch64_remote":
            host = request.getfixturevalue("remote_host")
            kwargs.pop("aslr", None)
            argv = [target] if isinstance(target, str) else list(target)
            binary = kwargs.pop("binary", argv[0])
            host.copy_libraries(Path.cwd())
            server = host.start_gdbserver([host.remote_path(Path(argv[0]).name), *argv[1:]], env=kwargs.pop("env", None))
            try:
                dbg = build(server.address, binary=binary, **kwargs)
            except BaseException:
                server.stop()
                raise
            dbg.p = server.tube
            remote_servers.append(server)
        elif backend == "remote":
            env = kwargs.pop("env", None)
            kwargs.pop("aslr", None)  # gdbserver disables the randomization by default
            binary = kwargs.pop("binary", target if isinstance(target, str) else None)
            server, address = _start_gdbserver(target, env=env)
            try:
                dbg = build(address, binary=binary, **kwargs)
            except BaseException:
                _stop_gdbserver(server)
                raise
            dbg.p = server
        else:
            dbg = build(target, **kwargs)
        created.append(dbg)
        if backend == "libdebug":
            dbg.migrate(libdebug=True)
        elif backend == "new_libdebug":
            dbg.migrate(new_libdebug=True)
        return dbg

    yield factory

    passed = getattr(request.node, "report_call", None) is not None and request.node.report_call.passed
    leaks = []
    if passed and not request.node.get_closest_marker("allow_priority_leak"):
        for dbg in created:
            if not dbg.debugging or dbg.control.closed.is_set():
                continue
            with context.silent:
                if dbg.running:  # a c(wait=False) still in flight legitimately holds a priority
                    continue
            if dbg.control.priority.suspended:  # so do the actions interrupt() suspended, until resume()
                continue
            deadline = time.time() + 2
            while dbg.priority != 0 and time.time() < deadline:
                time.sleep(0.05)
            if dbg.priority != 0:
                leaks.append(f"[{dbg.pid}] priority {dbg.priority}")
    for dbg in reversed(created):
        _shutdown(dbg, local=not any(server.tube is dbg.p for server in remote_servers))
    for server in remote_servers:
        server.stop()
    log = getattr(request.node, "gdb_terminal_log", None)
    if log is not None:
        _kill_terminals_of(log)
    if leaks:
        pytest.fail("wait priority not back to 0 after the test: " + ", ".join(leaks), pytrace=False)


########################## SHUTDOWN ##########################

def pytest_sessionfinish(session, exitstatus):
    session.config._gdb_plus_exitstatus = int(exitstatus)


def pytest_unconfigure(config):
    # gdb_plus starts non daemon threads that may still wait on a debugger that a failed test left behind.
    # They would keep the interpreter alive forever after the summary has been printed.
    lingering = [t for t in threading.enumerate()
                 if t is not threading.main_thread() and not t.daemon and t.is_alive()]
    if lingering and hasattr(config, "_gdb_plus_exitstatus"):
        # os._exit skips atexit, where pwntools kills the gdb terminals: run it ourselves first
        try:
            atexit._run_exitfuncs()
        except Exception:
            pass
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(config._gdb_plus_exitstatus)
