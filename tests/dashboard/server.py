#!/usr/bin/env python3
"""
Dashboard of the gdb_plus test suite: feature x domain matrix, evolution between versions, runs.

    python3 tests/dashboard/server.py              # http://127.0.0.1:8642, can also start pytest
    python3 tests/dashboard/server.py --open       # same, and open the browser
    python3 tests/dashboard/server.py --export report.html   # standalone read only page (CI artifacts)

The results come from tests/.results/<version>.json, written by the support/results.py plugin on every
pytest run (from the terminal or from the dashboard). Only the standard library is needed.
"""
import argparse
import collections
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent
REPO = TESTS.parent
RESULTS = Path(os.environ.get("GDB_PLUS_RESULTS_DIR", TESTS / ".results"))
PAGE = HERE / "index.html"
TOKEN = secrets.token_hex(16)
FLAVORS = ["vanilla", "gef", "pwndbg", "user"]


def library_version():
    match = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    return match.group(1) if match else "unknown"


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (OSError, TypeError):
        return False


def load_data():
    versions = []
    for path in sorted(RESULTS.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and "results" in data:
            versions.append(data)
    return {"versions": versions, "current": library_version(), "generated": time.time(), "catalog": load_catalog()}


CATALOG = RESULTS / "catalog.json"
CATALOG_LOCK = threading.Lock()


def _sources_changed(since):
    for path in TESTS.rglob("*.py"):
        if ".results" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            if path.stat().st_mtime > since:
                return True
        except OSError:
            pass
    return False


def load_catalog():
    """
    What every feature checks (its docstring) and why its absent domains are absent (the reasons of its markers),
    collected from the test files as they are now, so an edited docstring or reason shows without running the
    tests again. Cached in .results/catalog.json and collected again when a test file changes (about a second).
    """
    with CATALOG_LOCK:
        try:
            cached = json.loads(CATALOG.read_text())
        except (OSError, ValueError):
            cached = None
        if cached is not None and not _sources_changed(cached.get("generated", 0)):
            return cached["features"]
        try:
            RESULTS.mkdir(parents=True, exist_ok=True)
            subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--collect-only", "-q", "--no-record",
                            f"--catalog={CATALOG}"], cwd=TESTS, capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
            return json.loads(CATALOG.read_text())["features"]
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            return cached["features"] if cached else {}


def load_lives():
    """Progress of the pytest runs: the running ones, then the last finished one. Older files are deleted."""
    lives = []
    for path in (RESULTS / "live").glob("*.json"):
        try:
            live = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        live["running"] = live.get("finished") is None and _alive(live.get("pid"))
        live["file"] = path
        lives.append(live)
    lives.sort(key=lambda live: (not live["running"], -live.get("updated", 0)))
    finished = [live for live in lives if not live["running"]]
    for live in finished[1:]:
        # A dead run that never finished waits for the next pytest, which records its hung test
        if live.get("finished") is not None:
            live["file"].unlink(missing_ok=True)
    lives = [live for live in lives if live["running"]] + finished[:1]
    for live in lives:
        del live["file"], live["path"]
    return lives


def live_state():
    lives = load_lives()
    own = RUNNER.process.pid if RUNNER.process is not None else None
    # the run started from the dashboard first, else the most recently updated one
    lives.sort(key=lambda live: (live.get("pid") != own or not live["running"], not live["running"]))
    return {"live": lives[0] if lives else None, "lives": lives, "runner": RUNNER.state(),
            "stamp": max([live.get("updated", 0) for live in lives], default=None)}


########################## RUNNER ##########################

class Runner:
    """One pytest at a time, started from the dashboard. Runs from a terminal show up through .results/live/."""

    def __init__(self):
        self.process = None
        self.command = None
        self.started = None
        self.returncode = None
        self.log = collections.deque(maxlen=3000)
        self.lock = threading.Lock()

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None

    def start(self, request):
        with self.lock:
            if self.running:
                raise ValueError("a run started from the dashboard is already in progress")
            command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rN"]
            for target in request.get("targets") or []:
                if not isinstance(target, str) or target.startswith("-") or ".." in Path(target.split("::")[0]).parts:
                    raise ValueError(f"invalid target {target!r}")
                command.append(target)
            if request.get("keyword"):
                command += ["-k", str(request["keyword"])]
            if request.get("markers"):
                command += ["-m", str(request["markers"])]
            if request.get("flavor"):
                if request["flavor"] not in FLAVORS:
                    raise ValueError("unknown gdb flavor")
                command.append(f"--gdb-flavor={request['flavor']}")
            if request.get("record_as"):
                command.append(f"--record-as={request['record_as']}")
            command += shlex.split(request.get("extra") or "")
            self.log.clear()
            self.log.append("$ " + self.display(command))
            environment = dict(os.environ, PYTHONUNBUFFERED="1", COLUMNS="140")
            self.process = subprocess.Popen(command, cwd=TESTS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, env=environment, start_new_session=True)
            self.command = command
            self.started = time.time()
            self.returncode = None
            threading.Thread(target=self._read, args=(self.process,), daemon=True).start()

    @staticmethod
    def display(command):
        return shlex.join(["pytest", *command[3:]])  # without "python -m"

    def _read(self, process):
        for line in iter(process.stdout.readline, b""):
            self.log.append(re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line.decode(errors="replace").rstrip("\n")))
        process.wait()
        self.returncode = process.returncode
        self.log.append(f"[exit status {process.returncode}]")

    def stop(self):
        """First call: SIGINT (pytest still saves the results). Second call: kill the whole process group."""
        process = self.process
        if process is not None and process.poll() is None:
            if getattr(process, "_interrupted", False):
                os.killpg(process.pid, signal.SIGKILL)
                self.log.append("[killed]")
            else:
                process._interrupted = True
                process.send_signal(signal.SIGINT)
                self.log.append("[interrupted: stop again to kill gdb and the debugged processes]")
            return
        raise ValueError("no run started from the dashboard is in progress")

    def state(self):
        return {"running": self.running, "command": self.command and self.display(self.command),
                "started": self.started, "returncode": self.returncode, "log": list(self.log)[-400:]}


RUNNER = Runner()


########################## HTTP ##########################

class Handler(BaseHTTPRequestHandler):
    server_version = "gdb_plus-dashboard"

    def log_message(self, format, *args):
        pass

    def _send(self, body, content_type="application/json", status=HTTPStatus.OK):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _trusted_host(self):
        # DNS rebinding: a page of another site resolving to 127.0.0.1 sends its own Host
        if self.server.server_address[0] not in ["127.0.0.1", "::1", "localhost"]:
            return True  # --host chose to expose the dashboard: the token still guards the POSTs
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in ["localhost", "127.0.0.1", "::1"]

    def do_GET(self):
        if not self._trusted_host():
            return self._send({"error": "forbidden host"}, status=HTTPStatus.FORBIDDEN)
        path = self.path.split("?")[0]
        if path in ["/", "/index.html"]:
            page = PAGE.read_text().replace("__DASHBOARD_TOKEN__", TOKEN)
            return self._send(page.encode(), "text/html; charset=utf-8")
        if path == "/api/data":
            return self._send(load_data())
        if path == "/api/state":
            return self._send(live_state())
        self._send({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        # A custom header can't be sent cross origin without a CORS preflight, which we never accept
        if not self._trusted_host() or self.headers.get("X-Dashboard-Token") != TOKEN:
            return self._send({"error": "forbidden"}, status=HTTPStatus.FORBIDDEN)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/run":
                RUNNER.start(request)
            elif self.path == "/api/stop":
                RUNNER.stop()
            else:
                return self._send({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
        except (ValueError, OSError) as error:
            return self._send({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
        self._send(live_state())


def export(destination):
    data = json.dumps(load_data(), separators=(",", ":")).replace("</", "<\\/")
    page = PAGE.read_text().replace('<script id="embedded-data" type="application/json"></script>',
                                    f'<script id="embedded-data" type="application/json">{data}</script>')
    Path(destination).write_text(page)
    print(f"wrote {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=int(os.environ.get("GDB_PLUS_DASHBOARD_PORT", 8642)))
    parser.add_argument("--host", default="127.0.0.1", help="interface to listen on (default: localhost only)")
    parser.add_argument("--open", action="store_true", help="open the dashboard in the browser")
    parser.add_argument("--export", metavar="FILE", help="write a standalone read only page and exit")
    args = parser.parse_args()
    if args.export:
        return export(args.export)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{'localhost' if args.host in ['127.0.0.1', '0.0.0.0'] else args.host}:{args.port}/"
    print(f"gdb_plus dashboard on {url}  (results in {RESULTS})")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if RUNNER.running:
            os.killpg(RUNNER.process.pid, signal.SIGINT)


if __name__ == "__main__":
    main()
