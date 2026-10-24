"""
pytest plugin: records the outcome and the timing of every test in tests/.results/<version>.json for the
dashboard (tests/dashboard). Loaded by tests/conftest.py.

One file per library version (pyproject.toml), holding the latest result of every test for each gdb flavor
and the result before it. Running a subset only replaces the tests that ran, so `pytest tests/unit` doesn't
erase the integration results of an earlier run.

Every result belongs to a feature (the test function and its parameters other than the target) and a domain:
    offline       unit tier, no debugger
    gdb           local x86-64 process debugged with gdb
    libdebug      legacy libdebug fork
    new_libdebug  libdebug >= 0.8
    remote        gdbserver, debugged through Debugger((host, port))
    i386          32 bit x86, native, gdb
    arm aarch64 riscv32 riscv64 mips mips64     qemu-user + gdb-multiarch
    aarch64_native                              planned: the whole suite on a real arm64 machine (the Raspberry Pi)
    aarch64_remote                              the gdbserver of an arm64 machine (--remote-gdbserver), debugged
                                                from here: only integration/test_gdbserver.py so far, see PLANNED
The domain comes from @pytest.mark.domain(name), else a parameter whose value is a domain (the `backend`
target axis of tests/integration), else the qemu(arch) / libdebug / new_libdebug markers, else gdb.

Every cell of the matrix is either a result or a justification. For the integration tier (where every
domain is expected) a feature that has no test on a domain must say why, with a marker on the test:
    @pytest.mark.not_applicable(domain, reason)   the feature can't exist there by design
    @pytest.mark.untested(domain, reason)         it could, but this suite doesn't test it, and why
    @pytest.mark.known_gap(domain, reason)        gdb_plus doesn't support it yet (to be fixed). run=False
                                                  if the run would hang: it is then never tried
`domain` can also be a group (see GROUPS: "qemu", "foreign", "libdebugs", "native", ...).
On a test parametrized over that domain the marker skips (or xfails) the matching runs at collection.
On a test that never runs there it records a declared cell without running anything. A missing domain
without a marker is recorded as "missing", the dashboard's way to say that an absence is not justified.
The unit and regression tiers only expect the domains they run on (see SCOPES).

Statuses: working, failing, not_implemented (xfail / NotImplementedError), not_applicable, not_covered
(justified absence), not_run (skipped because the machine lacks something), missing (unjustified absence).

Under pytest-xdist (pytest -n 8) the workers run the tests and only the controller writes the file: a Worker plugin
attaches what the Recorder would compute from the items to the reports (user_properties) and sends the declared
cells of the collection in workeroutput, when the worker finishes.
"""
import fcntl
import inspect
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent.parent
REPO = TESTS.parent
RESULTS = Path(os.environ.get("GDB_PLUS_RESULTS_DIR", TESTS / ".results"))
QEMU_ARCHES = ["arm", "aarch64", "riscv32", "riscv64", "mips", "mips64"]
# Values of the `backend` target axis of tests/integration (and of any parameter that picks a domain)
BACKENDS = ["gdb", "libdebug", "new_libdebug", "remote", "i386", *QEMU_ARCHES]
# Domains of the matrix that most features don't run on yet: an integration feature without a test there gets a "not
# covered" cell with this reason instead of "missing". They are in no group, so the markers written for the other
# targets don't decide for them
PLANNED = {
    "aarch64_native": "planned, no harness yet: gdb_plus, gdb and the process all on a real arm64 machine "
                      "(the Raspberry Pi, tests/arm_pi_test_plan.md part A)",
    "aarch64_remote": "this test doesn't take the target axis: it never runs on the gdbserver of the arm64 machine of "
                      "--remote-gdbserver (tests/arm_pi_test_plan.md part B)",
}
DOMAINS = ["offline", *BACKENDS, *PLANNED]
GROUPS = {
    "native": ["gdb", "libdebug", "new_libdebug"],        # a local x86-64 process
    "libdebugs": ["libdebug", "new_libdebug"],
    "gdb_only": [*(d for d in BACKENDS if d not in ["libdebug", "new_libdebug"]), "aarch64_remote"],  # every domain that goes through gdb
    "not_gdb": [*(d for d in BACKENDS if d != "gdb"), "aarch64_remote"],
    "qemu": QEMU_ARCHES,
    "foreign": ["i386", *QEMU_ARCHES, "aarch64_remote"],   # every architecture but x86-64
    "32bit": ["i386", "arm", "riscv32", "mips"],
}
TIERS = ["unit", "integration", "regression"]
# Domains a feature of each tier is expected to have a cell for, and why the others are empty
SCOPES = {
    "unit": {"domains": ["offline"], "reason": "unit tier: pure logic checked without a process"},
    "integration": {"domains": [*BACKENDS, *PLANNED], "reason": "integration tier: every feature runs on a real process (the offline column is the unit tier)"},
    "regression": {"domains": None, "reason": "regression tier: a legacy script replayed on the domain it was written for"},
}
KEEP_RUNS = 200
FLUSH_EVERY = 2  # seconds: writing the file after every unit test would double the time of the unit tier
NOT_APPLICABLE = re.compile(r"^(skipped:\s*)?not applicable\b[:\s]*", re.I)
NOT_COVERED = re.compile(r"^(skipped:\s*)?not covered\b[:\s]*", re.I)
DECLARATIONS = {"not_applicable": "not_applicable", "untested": "not_covered", "known_gap": "not_implemented"}


def pytest_addoption(parser):
    group = parser.getgroup("gdb_plus")
    group.addoption("--no-record", action="store_true", help="don't save the results for the dashboard")
    group.addoption("--record-as", default=os.environ.get("GDB_PLUS_RESULTS_VERSION"),
                    help="version under which the results are saved. Default: the version in pyproject.toml")
    group.addoption("--catalog", metavar="FILE", help="write what every collected feature checks and the reasons of "
                                                      "its markers to FILE (the dashboard runs it with --collect-only)")


def pytest_configure(config):
    config.addinivalue_line("markers", "domain(name): domain of the test in the dashboard (offline, gdb, libdebug, "
                                       "new_libdebug, remote, i386, arm, aarch64, riscv32, riscv64, mips, mips64, aarch64_native, aarch64_remote)")
    config.addinivalue_line("markers", "not_applicable(domain, reason): the feature can't exist on that domain (or group)")
    config.addinivalue_line("markers", "untested(domain, reason): the feature could exist on that domain, why it isn't tested")
    config.addinivalue_line("markers", "known_gap(domain, reason, run=True): gdb_plus doesn't support the feature there yet")
    if config.getoption("--catalog") and not hasattr(config, "workerinput"):
        config.pluginmanager.register(Catalog(config.getoption("--catalog")), "gdb_plus_catalog")
    if config.getoption("--no-record") or config.getoption("--collect-only"):
        return
    if hasattr(config, "workerinput"):
        config.pluginmanager.register(Worker(config), "gdb_plus_results_worker")
        return
    config.pluginmanager.register(Recorder(config), "gdb_plus_results")


########################## CLASSIFICATION ##########################

def library_version():
    try:
        match = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    except OSError:
        match = None
    return match.group(1) if match else "unknown"


def _git(*args):
    try:
        return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _host():
    try:
        return platform.freedesktop_os_release().get("PRETTY_NAME", platform.platform())
    except (OSError, AttributeError):
        return platform.platform()


def _tier(item):
    try:
        parts = Path(str(item.fspath)).relative_to(TESTS).parts
    except ValueError:
        return None
    return parts[0] if parts and parts[0] in TIERS else None


def expand(spec):
    """A domain or a group name -> list of domains"""
    return GROUPS.get(spec, [spec])


def declarations(item, *, options=False):
    """
    [(domain, status, reason)] declared by the not_applicable / untested / known_gap markers of an item, the
    closest marker first. With options=True each tuple also has the keyword arguments of the marker
    (known_gap(..., run=False) for a gap that would hang).
    """
    declared = []
    for marker in item.iter_markers():
        if marker.name not in DECLARATIONS:
            continue
        spec = marker.args[0] if marker.args else marker.kwargs.get("domain")
        reason = marker.args[1] if len(marker.args) > 1 else marker.kwargs.get("reason", "")
        extra = {key: value for key, value in marker.kwargs.items() if key not in ["domain", "reason"]}
        for domain in expand(spec):
            declared.append((domain, DECLARATIONS[marker.name], reason, extra) if options else (domain, DECLARATIONS[marker.name], reason))
    return declared


def domain_of(item):
    """(domain, name of the parameter that chose it or None)"""
    marker = item.get_closest_marker("domain")
    if marker is not None:
        return marker.args[0], None
    if _tier(item) == "unit":
        return "offline", None
    callspec = getattr(item, "callspec", None)
    if callspec is not None:
        for name, value in callspec.params.items():
            if isinstance(value, str) and (value in BACKENDS or value in PLANNED):
                return value, name
    marker = item.get_closest_marker("qemu")
    if marker is not None:
        return (marker.args[0] if marker.args and marker.args[0] in DOMAINS else "qemu"), None
    for backend in ["new_libdebug", "libdebug"]:
        if item.get_closest_marker(backend):
            return backend, None
    return "gdb", None


def feature_of(item, domain_param):
    """Identity of the row in the dashboard: the same for every domain the test runs on."""
    path = Path(str(item.fspath))
    try:
        relative = path.relative_to(TESTS).as_posix()
    except ValueError:
        relative = path.name
    name = getattr(item, "originalname", None) or item.name.split("[")[0]
    params = []
    callspec = getattr(item, "callspec", None)
    if callspec is not None:
        skip = callspec.params.get(domain_param) if domain_param else None
        params = [part for part in callspec.id.split("-") if part != skip]
    title = re.sub(r"^test_", "", name).replace("_", " ")
    if params:
        title += f" [{', '.join(params)}]"
    key = f"{relative}::{name}" + (f"[{'-'.join(params)}]" if params else "")
    function = getattr(item, "function", None)
    # One paragraph per blank line: the line breaks of the docstring are only there to fit 120 columns
    doc = "\n\n".join(" ".join(part.split()) for part in inspect.cleandoc(function.__doc__ or "").split("\n\n")) if function else ""
    return key, title, doc


def area_of(item):
    tier = _tier(item) or "other"
    stem = re.sub(r"^test_", "", Path(str(item.fspath)).stem).replace("_", " ")
    module = getattr(item, "module", None)
    doc = ((module.__doc__ if module is not None else None) or "").strip().split("\n\n")[0].replace("\n", " ")
    return tier, stem, doc


def _crash_message(report):
    longrepr = report.longrepr
    crash = getattr(longrepr, "reprcrash", None)
    if crash is not None:
        return crash.message
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr).strip().splitlines()[-1] if longrepr else ""


def _skip_reason(report):
    longrepr = report.longrepr
    reason = longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) == 3 else str(longrepr or "")
    return re.sub(r"^Skipped:\s*", "", reason)


def classify(phases):
    """phases: {when: (report, raised NotImplementedError)} -> (status, message, details, flags)"""
    for when in ["setup", "call"]:
        if when not in phases:
            continue
        report, not_implemented = phases[when]
        if report.skipped:
            if hasattr(report, "wasxfail"):
                return "not_implemented", report.wasxfail, "", []
            reason = _skip_reason(report)
            if NOT_APPLICABLE.match(reason):
                return "not_applicable", NOT_APPLICABLE.sub("", reason), "", []
            if NOT_COVERED.match(reason):
                return "not_covered", NOT_COVERED.sub("", reason), "", []
            return "not_run", reason, "", []
        if report.failed:
            details = report.longreprtext[-4000:]
            if not_implemented:
                return "not_implemented", _crash_message(report), details, ["NotImplementedError"]
            if "XPASS(strict)" in details:
                return "failing", "passed although marked as a known gap: " + details.replace("[XPASS(strict)]", "").strip(), "", ["xpass"]
            flags = ["error in setup"] if when == "setup" else []
            return "failing", _crash_message(report), details, flags
    flags = ["xpass"] if "call" in phases and hasattr(phases["call"][0], "wasxfail") else []
    if "teardown" in phases and phases["teardown"][0].failed:
        report = phases["teardown"][0]
        return "failing", _crash_message(report), report.longreprtext[-4000:], ["error in teardown"]
    return "working", "", "", flags


def describe(item):
    """Where a test goes in the dashboard: its feature (row) and domain (column)."""
    domain, domain_param = domain_of(item)
    feature, title, doc = feature_of(item, domain_param)
    tier, area, area_doc = area_of(item)
    return {"nodeid": item.nodeid, "domain": domain, "feature": feature, "title": title, "doc": doc,
            "tier": tier, "area": area, "area_doc": area_doc}


def catalog(items):
    """
    {feature: {"title", "doc", "tier", "area", "area_doc", "declared": {domain: [status, reason]}}} of the collected
    items, read from the test files as they are now: the dashboard shows it instead of the descriptions and
    reasons saved with the results, which are only as recent as the run of each test.
    """
    features = {}
    for item in items:
        info = describe(item)
        feature = features.setdefault(info["feature"], {name: info[name] for name in ["title", "doc", "tier", "area", "area_doc"]})
        declared = feature.setdefault("declared", {})
        for domain, status, reason in declarations(item):
            declared.setdefault(domain, [status, reason])
    return features


class Catalog:
    def __init__(self, path):
        self.path = Path(path)

    def pytest_collection_finish(self, session):
        temporary = self.path.with_suffix(f".tmp{os.getpid()}")
        temporary.write_text(json.dumps({"generated": time.time(), "features": catalog(session.items)}, separators=(",", ":")))
        temporary.replace(self.path)


########################## STORAGE ##########################

def merge(path, version, pending, run, collected=None):
    """
    Add the results of `run` to the file of a version. Call with RESULTS/.lock held.
    collected: {test file: node ids} of the files this run collected (selected or deselected): the results of
    tests that are not in their file any more (renamed, deleted) are dropped, for the flavor of the run.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        data = {}
    data.setdefault("format", 1)
    data["version"] = version
    data["domains"] = DOMAINS
    data["scopes"] = SCOPES
    results = data.setdefault("results", {})
    if collected:
        for key in list(results):
            flavor, _, nodeid = key.partition("|")
            nodeid = nodeid.split("@")[0]
            if flavor == run["flavor"] and nodeid.split("::")[0] in collected and nodeid not in collected[nodeid.split("::")[0]]:
                del results[key]
    for key, entry in pending.items():
        entry["run"] = run["id"]
        entry["commit"] = run["commit"]
        entry["flavor"] = run["flavor"]
        old = results.get(key)
        if old is not None:
            # Keep the result of the previous run, not the one written a few seconds ago by this run
            entry["previous"] = old.get("previous") if old.get("run") == run["id"] else {
                name: old.get(name) for name in ["status", "duration", "when", "commit", "message"]}
        results[key] = entry
    runs = [r for r in data.get("runs", []) if r.get("id") != run["id"]]
    previous = next((r for r in data.get("runs", []) if r.get("id") == run["id"]), {})
    runs.append(dict(previous, **run))
    data["runs"] = runs[-KEEP_RUNS:]
    data["updated"] = time.time()
    temporary = path.with_suffix(f".tmp{os.getpid()}")
    temporary.write_text(json.dumps(data, separators=(",", ":")))
    temporary.replace(path)


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError):
        return False


def recover_stopped_runs():
    """
    A run killed by the watchdog (a test hung inside C code) never reports its last test. Its live file still
    names it: record it as failing, with the thread dump of tests/.watchdog-<pid>.txt. Call with the lock held.
    """
    for live_path in (RESULTS / "live").glob("*.json"):
        try:
            live = json.loads(live_path.read_text())
        except (OSError, ValueError):
            continue
        if live.get("finished") is not None or _alive(live.get("pid")) or not live.get("path"):
            continue
        current = live.get("current")
        if isinstance(current, dict):
            watchdog = TESTS / f".watchdog-{live['pid']}.txt"
            try:
                details = watchdog.read_text()[:4000]
            except OSError:
                details = ""
            current.pop("started", None)
            key = f"{live.get('flavor', 'vanilla')}|{current['nodeid']}"
            message = ("hung: the watchdog stopped the run during this test" if details else
                       "the run stopped during this test (killed, or hung)")
            entry = dict(current, status="failing", message=message, details=details, flags=["hung"],
                         duration=None, setup=None, call=None, when=live["updated"])
            run = {"id": live["run"], "commit": live.get("commit", ""), "flavor": live.get("flavor", "vanilla"),
                   "stopped": current["nodeid"], "done": live.get("done")}
            merge(Path(live["path"]), live["version"], {key: entry}, run)
        live["finished"] = live["updated"]
        live["stopped"] = True
        live_path.write_text(json.dumps(live))


########################## RESULTS OF A RUN ##########################

def entry_of(item, phases):
    """The saved result of a test that ran (the Recorder adds the fields of the run)"""
    status, message, details, flags = classify(phases)
    common = describe(item)
    domain = common.pop("domain")
    common.pop("nodeid")
    return dict(common,
                nodeid=item.nodeid,
                domain=domain,
                status=status,
                message=message[:600],
                details=details,
                flags=flags,
                duration=round(sum(r.duration for r, _ in phases.values()), 4),
                setup=round(phases["setup"][0].duration, 4) if "setup" in phases else None,
                call=round(phases["call"][0].duration, 4) if "call" in phases else None,
                when=time.time())


def declared_cells(selected, deselected):
    """
    {feature@domain: entry}: one declared cell for every domain that a feature selected in this run is expected to
    have but no test runs on: the reason of its marker, or "missing". Deselected tests count as present (they exist).
    """
    features = {}
    for item in [*selected, *deselected]:
        info = describe(item)
        feature = features.setdefault(info["feature"], {"info": info, "domains": set(), "declared": {},
                                                        "selected": False, "nodeid": item.nodeid})
        feature["domains"].add(info["domain"])
        for domain, status, reason in declarations(item):
            feature["declared"].setdefault(domain, (status, reason))
    for item in selected:
        features[describe(item)["feature"]]["selected"] = True
    now = time.time()
    cells = {}
    for key, feature in features.items():
        info = feature["info"]
        expected = SCOPES.get(info["tier"], {}).get("domains") or []
        if not feature["selected"]:
            continue
        for domain in expected:
            if domain in feature["domains"]:
                continue
            status, reason = feature["declared"].get(domain, ("not_covered", PLANNED[domain]) if domain in PLANNED else (
                "missing", "no test of this feature on this domain, and no marker that says why"))
            common = {name: value for name, value in info.items() if name not in ["nodeid", "domain"]}
            cells[f"{key}@{domain}"] = dict(
                common, nodeid=f"{feature['nodeid']}@{domain}", domain=domain, status=status, message=reason,
                details="", flags=["declared"], duration=None, setup=None, call=None, when=now)
    return cells


def collection_summary(session, deselected):
    """(declared cells, {test file: node ids}) of a collection: what merge() needs besides the results"""
    # A file named with ::test was only partly collected: its other tests still exist, on other domains too
    partial = set()
    for argument in session.config.args:
        if "::" in argument:
            try:
                partial.add(Path(argument.split("::")[0]).resolve().relative_to(TESTS).as_posix())
            except ValueError:
                pass
    whole = [item for item in [*session.items, *deselected] if item.nodeid.split("::")[0] not in partial]
    declared = declared_cells([item for item in session.items if item in whole], [item for item in deselected if item in whole])
    collected = {}
    for item in [*session.items, *deselected]:
        path = item.nodeid.split("::")[0]
        if path not in partial:
            collected.setdefault(path, set()).add(item.nodeid)
    return declared, collected


def _phases(item, call, report):
    phases = item.__dict__.setdefault("_gdb_plus_phases", {})
    raised = call.excinfo is not None and call.excinfo.errisinstance(NotImplementedError)
    phases[report.when] = (report, raised)
    return phases


class Worker:
    """
    A pytest-xdist worker: it can't write the file (the controller does), it sends what only it can compute.
    The setup report carries the test's description (to record a test that crashes its worker), the teardown report
    the saved result, and workeroutput the declared cells of the collection (every worker collects the same tests).
    """
    def __init__(self, config):
        self.config = config
        self.deselected = []

    def pytest_deselected(self, items):
        self.deselected += items

    def pytest_collection_finish(self, session):
        declared, collected = collection_summary(session, self.deselected)
        self.config.workeroutput["gdb_plus_collection"] = {
            "declared": declared, "collected": {path: sorted(ids) for path, ids in collected.items()}}

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        phases = _phases(item, call, report)
        if report.when == "setup":
            report.user_properties.append(("gdb_plus_test", dict(describe(item), worker_pid=os.getpid())))
        elif report.when == "teardown":
            report.user_properties.append(("gdb_plus_entry", entry_of(item, phases)))


def _user_property(report, name):
    for prop in getattr(report, "user_properties", ()):
        if prop[0] == name:
            return prop[1]
    return None


########################## RECORDER ##########################

class Recorder:
    def __init__(self, config):
        self.config = config
        self.version = config.getoption("--record-as") or library_version()
        self.flavor = config.getoption("--gdb-flavor", "vanilla")
        self.path = RESULTS / f"{re.sub(r'[^A-Za-z0-9._+-]', '_', self.version)}.json"
        self.pending = {}
        self.last_flush = time.time()
        self.started = time.time()
        self.counts = {}
        self.deselected = []
        self.collected = {}  # sent once, with the first flush
        self.total = 0
        self.done = 0
        self.current = None
        # pytest -n: the controller only sees the reports of the workers (see Worker)
        self.xdist = getattr(config.option, "dist", "no") != "no"
        self.described = {}  # nodeid -> description, from the setup reports of the workers
        self.collection_received = False
        commit = _git("rev-parse", "--short", "HEAD")
        dirty = bool(_git("status", "--porcelain", "--untracked-files=no"))
        self.run = {
            "id": time.strftime("%Y%m%d-%H%M%S", time.localtime(self.started)) + f"-{os.getpid()}",
            "started": self.started,
            "finished": None,
            "version": self.version,
            "flavor": self.flavor,
            "commit": commit + ("+dirty" if dirty and commit else ""),
            "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "args": list(config.invocation_params.args),
            "python": platform.python_version(),
            "host": _host(),
            "pid": os.getpid(),
            "workers": getattr(config.option, "numprocesses", None) if self.xdist else None,
        }

    # ----------------------- hooks -----------------------

    def pytest_deselected(self, items):
        self.deselected += items

    def pytest_collection_finish(self, session):
        self.total = len(session.items)
        declared, self.collected = collection_summary(session, self.deselected)
        self.pending.update({f"{self.flavor}|{key}": entry for key, entry in declared.items()})
        self.flush(force=True)

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_protocol(self, item, nextitem):
        # Saved before the test starts: if the watchdog kills the run, the next run records this test as hung
        self.current = dict(describe(item), started=time.time())
        try:
            self._write_live()
        except OSError:
            pass

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        phases = _phases(item, call, report)
        if report.when == "teardown":
            self.record(item, phases)

    # ----------------------- pytest -n -----------------------

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        first = self.total == 0
        self.total = max(self.total, len(ids))  # every worker collects the same tests
        if first:
            self.flush(force=True)

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node, error):
        collection = getattr(node, "workeroutput", {}).get("gdb_plus_collection")
        if collection is None or self.collection_received:
            return
        self.collection_received = True
        self.pending.update({f"{self.flavor}|{key}": entry for key, entry in collection["declared"].items()})
        self.collected = {path: set(ids) for path, ids in collection["collected"].items()}
        self.flush(force=True)

    def pytest_runtest_logstart(self, nodeid, location):
        if self.xdist:
            self.current = {"nodeid": nodeid, "started": time.time()}  # one of the tests running now

    def pytest_runtest_logreport(self, report):
        if not self.xdist:
            return
        if report.when == "setup":
            described = _user_property(report, "gdb_plus_test")
            if described is not None:
                self.described[report.nodeid] = described
        elif report.when == "teardown":
            entry = _user_property(report, "gdb_plus_entry")
            if entry is not None:
                self.described.pop(report.nodeid, None)
                self._add(entry)
        elif report.when == "???":  # xdist: the worker died during the test (the watchdog stops hung tests)
            described = self.described.pop(report.nodeid, None)
            if described is None:
                return
            watchdog = TESTS / f".watchdog-{described.pop('worker_pid', None)}.txt"
            try:
                details = watchdog.read_text()[:4000]
                watchdog.unlink()
            except OSError:
                details = ""
            message = ("hung: the watchdog stopped the worker during this test" if details else
                       "the worker running this test crashed (killed, or hung)")
            self._add(dict(described, status="failing", message=message, details=details, flags=["hung"],
                           duration=None, setup=None, call=None, when=time.time()))

    def pytest_sessionfinish(self, session, exitstatus):
        self.run["finished"] = time.time()
        self.run["exitstatus"] = int(exitstatus)
        self.current = None
        self.flush(force=True)

    # ----------------------- records -----------------------

    def record(self, item, phases):
        self._add(entry_of(item, phases))

    def _add(self, entry):
        self.pending[f"{self.flavor}|{entry['nodeid']}"] = entry
        self.counts[entry["status"]] = self.counts.get(entry["status"], 0) + 1
        self.done += 1
        self.flush()

    def flush(self, force=False):
        if not force and time.time() - self.last_flush < FLUSH_EVERY:
            return
        self.last_flush = time.time()
        try:
            RESULTS.mkdir(parents=True, exist_ok=True)
            with open(RESULTS / ".lock", "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if force and self.done == 0:
                    recover_stopped_runs()
                merge(self.path, self.version, self.pending, dict(
                    self.run, total=self.total, done=self.done, counts=dict(self.counts),
                    duration=round(time.time() - self.started, 2)), collected=self.collected)
                self.pending = {}
                self.collected = {}
                self._write_live()
        except OSError as error:  # a read only checkout must not break the suite
            print(f"\n[results] can not save the results: {error}", file=sys.stderr)

    def _write_live(self):
        live = {"run": self.run["id"], "pid": os.getpid(), "version": self.version, "flavor": self.flavor,
                "path": str(self.path), "commit": self.run["commit"],
                "total": self.total, "done": self.done, "current": self.current, "counts": dict(self.counts),
                "started": self.started, "finished": self.run["finished"], "updated": time.time()}
        # One file per run: several pytest may run at the same time (the dashboard shows all of them)
        (RESULTS / "live").mkdir(parents=True, exist_ok=True)
        (RESULTS / "live" / f"{os.getpid()}.json").write_text(json.dumps(live))
