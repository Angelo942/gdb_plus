"""
One Backend per engine: what the Debugger does differently with gdb, legacy libdebug and new libdebug.
BackendsMixin._backend gives the one of the engine attached to the process.
"""
from gdb_plus.debugger.engines.base import Backend
from gdb_plus.debugger.engines.gdb import GdbBackend
from gdb_plus.debugger.engines.libdebug import LibdebugBackend
from gdb_plus.debugger.engines.new_libdebug import NewLibdebugBackend

__all__ = ["Backend", "GdbBackend", "LibdebugBackend", "NewLibdebugBackend"]
