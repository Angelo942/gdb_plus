import logging

DEBUG = False
_logger = logging.getLogger("gdb_plus")

class LevelColorFormatter(logging.Formatter):
    WHITE       = "\033[37m"
    BLUE        = "\033[34m"
    YELLOW      = "\033[33m"
    RED         = "\033[31m"
    BRIGHT_RED  = "\033[1;31m"

    LEVEL_COLORS = {
        logging.DEBUG:    WHITE,
        logging.INFO:     BLUE,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BRIGHT_RED,
    }

    def __init__(self, fmt=None, datefmt=None, style='%'):
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

    def format(self, record):
        RESET       = "\033[0m"
        msg = super().format(record)
        color = self.LEVEL_COLORS.get(record.levelno, RESET)
        return f"{color}{msg}{RESET}"
