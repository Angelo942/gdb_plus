"""
Local stand-ins for the remote services of a CTF, so REMOTE mode and gdbserver can be tested
without network access.
"""
import socket
import subprocess
import threading
from contextlib import contextmanager


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def serve_binary(argv, *, cwd=None, env=None):
    """Like `socat tcp-listen:PORT,fork exec:BINARY`: each connection gets a fresh process."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(0.2)
    stop = threading.Event()
    children = []

    def accept_loop():
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                children.append(subprocess.Popen(argv, stdin=connection.fileno(), stdout=connection.fileno(),
                                                 stderr=subprocess.DEVNULL, cwd=cwd, env=env))

    thread = threading.Thread(target=accept_loop, name="serve_binary", daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", server.getsockname()[1]
    finally:
        stop.set()
        server.close()
        for child in children:
            child.kill()
            child.wait()


@contextmanager
def gdbserver(argv, *, cwd=None):
    """Run `gdbserver 127.0.0.1:PORT argv...` and yield (host, port)."""
    port = free_port()
    process = subprocess.Popen(["gdbserver", f"127.0.0.1:{port}", *map(str, argv)], cwd=cwd,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    listening = threading.Event()

    # Don't probe the port: gdbserver would take the probe for the debugger
    def watch_output():
        for line in process.stdout:
            if b"Listening on port" in line:
                listening.set()

    threading.Thread(target=watch_output, name="gdbserver_output", daemon=True).start()
    try:
        if not listening.wait(10):
            raise RuntimeError("gdbserver did not start")
        yield "127.0.0.1", port
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
