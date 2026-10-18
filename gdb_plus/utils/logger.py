from __future__ import annotations
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Literal
    from pwnlib.log import Logger

# Crash on "should never happen" paths instead of warning.
# On for development and tests, off for users.
STRICT: bool = os.environ.get("GDB_PLUS_STRICT", "") not in ("", "0")

def unexpected(msg: str, log: Logger) -> None:
    if STRICT:
        raise RuntimeError(msg)
    log.warn_once(msg + " Please raise an issue.")

DEBUG: bool = STRICT
_logger = logging.getLogger("gdb_plus")

class LevelColorFormatter(logging.Formatter):
    WHITE       = "\033[37m"
    BLUE        = "\033[34m"
    YELLOW      = "\033[33m"
    RED         = "\033[31m"
    BRIGHT_RED  = "\033[1;31m"

    LEVEL_COLORS: dict[int, str] = {
        logging.DEBUG:    WHITE,
        logging.INFO:     BLUE,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BRIGHT_RED,
    }

    def __init__(self, fmt: str | None = None, datefmt: str | None = None, style: Literal["%", "{", "$"] = '%') -> None:
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

    def format(self, record: logging.LogRecord) -> str:
        RESET       = "\033[0m"
        msg = super().format(record)
        color = self.LEVEL_COLORS.get(record.levelno, RESET)
        return f"{color}{msg}{RESET}"
