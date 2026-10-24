"""
The arm64 machine of --remote-gdbserver=user@host (the aarch64_remote target, a Raspberry Pi): the fixtures are built
there, run under its gdbserver and debugged from this machine with gdb-multiarch.

gdbserver has no authentication and can run anything, so it only listens on the loopback of that machine: the port is
forwarded to the same port of this machine by the ssh session that runs it. ssh must log in without a password
(BatchMode): use a key, and ~/.ssh/config for anything else (user, port, identity).
"""
import io
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import threading
from contextlib import contextmanager
from pathlib import Path

from support.local_server import free_port

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SSH = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5"]
# Where the fixtures are copied and built, relative to the home of the remote user
REMOTE_DIRECTORY = ".cache/gdb_plus_tests"

class RemoteHost:
    """
    One ssh destination, set up once per session by the remote_host fixture (tests/conftest.py): setup() checks the
    tools, copies tests/fixtures there and finds its architecture. Every method blocks until ssh returns.
    """
    def __init__(self, destination: str, cache: Path):
        self.destination = destination
        self.cache = cache  # local copies of the binaries built on the host
        self.arch = None
        self.directory = None

    def run(self, command: str, *, stdin: bytes = None, timeout: float = 120) -> bytes:
        """Run a shell command on the host and return its stdout. Raises RuntimeError with its stderr if it fails."""
        result = subprocess.run([*SSH, self.destination, command], input=stdin, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            error = result.stderr.decode(errors="replace").strip()
            raise RuntimeError(f"ssh {self.destination} {command!r} failed ({result.returncode}): {error}")
        return result.stdout

    def setup(self):
        """Check that the host has gdbserver and a compiler and copy the sources of the fixtures there."""
        self.arch = self.run("uname -m").decode().strip()
        missing = self.run("for tool in gdbserver make gcc flock; do command -v $tool >/dev/null || echo $tool; done").split()
        if missing:
            raise RuntimeError(f"{self.destination} lacks {', '.join(tool.decode() for tool in missing)}")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            tar.add(FIXTURES / "Makefile", "Makefile")
            tar.add(FIXTURES / "src", "src")
        # tar keeps the modification times of the sources: make only rebuilds what changed since the last session.
        # flock: every pytest-xdist worker sets up its own session, all in the same directory
        command = f"mkdir -p {REMOTE_DIRECTORY} && cd {REMOTE_DIRECTORY} && flock .lock tar -xf - && pwd"
        self.directory = self.run(command, stdin=archive.getvalue()).decode().strip()

    def remote_path(self, name: str) -> str:
        """Path on the host of the fixture `name` (built by binary())"""
        return f"{self.directory}/bin/{name}"

    def binary(self, name: str, destination: Path) -> str:
        """
        Build the fixture `name` on the host (make, with the Makefile of tests/fixtures) and copy it into `destination`,
        for Debugger(binary=). Returns the local path, which has the same file name as the remote one.
        """
        local = self.cache / name
        if not local.exists():
            self.run(f"cd {shlex.quote(self.directory)} && flock .lock make -s bin/{name}", timeout=300)
            self.cache.mkdir(parents=True, exist_ok=True)
            local.write_bytes(self.read_file(self.remote_path(name)))
            local.chmod(0o755)
        copy = Path(destination) / name
        if not copy.exists():
            shutil.copy(local, copy)
        return str(copy)

    def copy_libraries(self, destination: Path):
        """
        Copy the libraries the fixtures load on the host (ldd of basic) into destination/gdb_files, where gdb_plus looks
        for the local copy of a remote file before anything else. Without them it would take the symbols of this
        machine's own aarch64 libc (a cross toolchain's), which isn't the host's.
        """
        libraries = self.cache / "gdb_files"
        if not libraries.exists():
            output = self.run(f"ldd {shlex.quote(self.remote_path('basic'))}").decode()
            libraries.mkdir(parents=True)
            for path in re.findall(r"(/\S+) \(0x", output):
                (libraries / Path(path).name).write_bytes(self.read_file(path))
        shutil.copytree(libraries, Path(destination) / "gdb_files", dirs_exist_ok=True)

    def read_file(self, path: str) -> bytes:
        """Content of a file of the host"""
        return self.run(f"cat {shlex.quote(str(path))}")

    def kill(self, *pids: int):
        """SIGKILL processes of the host, ignoring the ones that already exited"""
        pids = [str(pid) for pid in pids if pid]
        if pids:
            self.run(f"kill -9 {' '.join(pids)} 2>/dev/null; true", timeout=30)

    @contextmanager
    def gdbserver(self, argv: list[str], *, env: dict[str, str] = None):
        """
        Run `gdbserver 127.0.0.1:PORT argv...` on the host and forward PORT of this machine to it. Yields
        (tube, (host, port)): the tube is the program's stdin and stdout through ssh, gdbserver's messages stay out of
        it. On exit the program and gdbserver are killed on the host: closing ssh doesn't stop them (no terminal, no
        SIGHUP).
        """
        server = self.start_gdbserver(argv, env=env)
        try:
            yield server.tube, server.address
        finally:
            server.stop()

    def start_gdbserver(self, argv: list[str], *, env: dict[str, str] = None, attempts: int = 3) -> "RemoteGdbserver":
        """gdbserver() without the context manager: the caller calls stop() on the result."""
        for _ in range(attempts):
            server = RemoteGdbserver(self, argv, env=env)
            if server.start():
                return server
            if not server.port_in_use:
                break
        raise RuntimeError(f"gdbserver did not start on {self.destination}: {server.output.decode(errors='replace')}")

class RemoteGdbserver:
    """A gdbserver started on a RemoteHost through `ssh -L PORT:127.0.0.1:PORT`. Built by RemoteHost.start_gdbserver."""
    def __init__(self, host: RemoteHost, argv: list[str], *, env: dict[str, str] = None):
        self.host = host
        # The same port on both sides: free here, and almost certainly free on the host (start() retries if it isn't)
        self.port = free_port()
        self.address = ("127.0.0.1", self.port)
        environment = "env -i " + " ".join(shlex.quote(f"{key}={value}") for key, value in env.items()) + " " if env is not None else ""
        arguments = " ".join(shlex.quote(str(argument)) for argument in argv)
        # $$ is the pid of the shell, which exec turns into gdbserver: the pid to kill on the host at the end
        self.command = (f"cd {shlex.quote(host.directory)} && echo \"gdbserver pid $$\" >&2 && "
                        f"exec {environment}gdbserver 127.0.0.1:{self.port} {arguments}")
        self.tube = None
        self.output = b""
        self.server_pid = None
        self.inferior_pid = None
        self.port_in_use = False

    def start(self) -> bool:
        """Start ssh and wait for gdbserver to listen. False if it didn't (the reason is in output)."""
        from pwn import context, process
        with context.local(log_level="error"):
            self.tube = process([*SSH, "-o", "ExitOnForwardFailure=yes", "-L", f"{self.port}:127.0.0.1:{self.port}",
                                 self.host.destination, self.command], stderr=subprocess.PIPE)
        listening, ended = threading.Event(), threading.Event()

        # Don't probe the port: gdbserver would take the probe for the debugger.
        # Read a copy of the pipe with os.read: a thread blocked in stream.readline() holds the lock of the stream and
        # process.close() would wait for it.
        def watch(fd):
            try:
                while chunk := os.read(fd, 0x1000):
                    self.output = (self.output + chunk)[-0x1000:]
                    if match := re.search(rb"gdbserver pid (\d+)", self.output):
                        self.server_pid = int(match.group(1))
                    if match := re.search(rb"pid = (\d+)", self.output):
                        self.inferior_pid = int(match.group(1))
                    if b"Listening on port" in self.output:
                        listening.set()
            finally:
                os.close(fd)
                ended.set()

        threading.Thread(target=watch, args=(os.dup(self.tube.proc.stderr.fileno()),), name="remote_gdbserver_stderr",
                         daemon=True).start()
        for _ in range(300):
            if listening.wait(0.1):
                return True
            if ended.is_set() or self.tube.poll() is not None:
                break
        self.port_in_use = b"Address already in use" in self.output
        self.stop()
        return False

    def stop(self):
        """Kill the program and gdbserver on the host, then close ssh."""
        try:
            self.host.kill(self.inferior_pid, self.server_pid)
        finally:
            if self.tube is not None:
                self.tube.close()

class RemoteMachine:
    """
    The arm64 machine seen from outside the debugged process, for the target_machine fixture (integration/conftest.py):
    the same methods as LocalMachine there. Each test gets its own directory under the build directory of the host.
    """
    def __init__(self, host: RemoteHost, name: str):
        self.host = host
        self.directory = f"{host.directory}/tmp/{name}"
        host.run(f"mkdir -p {shlex.quote(self.directory)}")

    def read_file(self, path: str) -> bytes:
        return self.host.read_file(path)

    def exists(self, path: str) -> bool:
        return self.host.run(f"test -e {shlex.quote(str(path))} && echo yes; true").strip() == b"yes"

    def write_file(self, path: str, data: bytes):
        self.host.run(f"cat > {shlex.quote(str(path))}", stdin=data)

    def temporary(self, name: str) -> str:
        """Path of a file named `name` in the directory of the test"""
        return f"{self.directory}/{name}"

    def signal(self, pid: int, name: str):
        """Send the signal `name` ("SIGCONT") to a process of the machine"""
        self.host.run(f"kill -{name.removeprefix('SIG')} {pid}")

    def program_path(self, local_path: str) -> str:
        """Path on the machine of the program whose local copy is local_path"""
        return self.host.remote_path(Path(local_path).name)
