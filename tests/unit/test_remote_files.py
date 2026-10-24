"""Where the local copy of a file of the debugged process is: local_path(), remote_path(), and connect()."""
from pathlib import Path

import pytest
from pwn import context

from support.offline import offline_debugger

LIBC = "/srv/remote/lib/libc.so.6"
MAPS = f"""\
0x400000  0x401000  0x1000  0x0  r-xp  /srv/remote/challenge
0x7ffff7d80000  0x7ffff7da8000  0x28000  0x0  r--p  {LIBC}
0x7ffff7da8000  0x7ffff7f3d000  0x195000  0x28000  r-xp  {LIBC}
"""


@pytest.fixture
def remote(monkeypatch, tmp_path):
    """A debugger of a gdbserver: no local process, the maps come from `info proc map`"""
    monkeypatch.chdir(tmp_path)
    with context.local(arch="amd64"):
        dbg = offline_debugger(local_debugging=False, raw_maps=MAPS)
        dbg.__dict__["downloaded"] = []

        def download(source, destination):
            dbg.downloaded.append((Path(source), Path(destination)))
            Path(destination).write_bytes(b"downloaded")
        dbg.__dict__["download"] = download
        yield dbg


def test_local_process_uses_the_path_itself(tmp_path, monkeypatch):
    """For a local process local_path() is the path itself: nothing to download."""
    monkeypatch.chdir(tmp_path)
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        assert dbg.local_path("/bin/sh") == Path("/bin/sh")


def test_remote_path_comes_from_the_maps(remote):
    """
    remote_path(name) finds the full path of a library on the remote host in its maps, and None for an unknown one.
    """
    assert remote.remote_path("libc.so.6") == Path(LIBC)
    assert remote.remote_path("missing.so") is None


def test_download_into_gdb_files(remote):
    """With download_libraries a remote library is downloaded into ./gdb_files and that copy is used."""
    remote.space.download_libraries = True
    assert remote.local_path(LIBC) == Path("gdb_files/libc.so.6")
    assert remote.downloaded == [(Path(LIBC), Path("gdb_files/libc.so.6"))]


def test_files_already_in_gdb_files_are_used(remote):
    """A library already in ./gdb_files is used without downloading it again."""
    # "if we have a gdb_files directory we assume that the libraries are here": no second download
    Path("gdb_files").mkdir()
    Path("gdb_files/libc.so.6").write_bytes(b"downloaded before")
    remote.space.download_libraries = True
    assert remote.local_path(LIBC) == Path("gdb_files/libc.so.6")
    assert remote.downloaded == []


def test_without_download_a_local_file_with_the_same_path_is_used(remote, tmp_path):
    """Without downloads, a local file at the same path as on the remote host is used."""
    copy = tmp_path / "same_path_here.so"
    copy.write_bytes(b"local")
    assert remote.local_path(str(copy)) == copy


def test_without_download_a_file_next_to_the_script_is_used(remote):
    """Without downloads, a file with the same name next to the script (the libc of the challenge) is used."""
    Path("libc.so.6").write_bytes(b"next to the script")
    assert remote.local_path(LIBC) == Path("libc.so.6")


def test_without_download_a_missing_file_is_none(remote):
    """Without downloads and without a local copy local_path() is None."""
    assert remote.local_path(LIBC) is None


def test_connect_needs_a_host():
    """connect() raises "host not set" when no remote host was given."""
    with context.local(arch="amd64"):
        dbg = offline_debugger(_host=None, _port=0)
        with pytest.raises(Exception, match="host not set"):
            dbg.connect()
