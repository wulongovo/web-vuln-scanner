"""Logging utility for the scanner."""

import logging
import sys
from datetime import datetime

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import config


def setup_logger(name="webvuln", level=logging.INFO):
    """Create a colored console logger."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Console handler with color
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)

    # Color codes
    COLORS = {
        logging.DEBUG: "\033[36m",     # cyan
        logging.INFO: "\033[32m",      # green
        logging.WARNING: "\033[33m",   # yellow
        logging.ERROR: "\033[31m",     # red
        logging.CRITICAL: "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    class ColorFormatter(logging.Formatter):
        def format(self, record):
            color = COLORS.get(record.levelno, RESET)
            record.msg = f"{color}{record.msg}{RESET}"
            return super().format(record)

    fmt = "[%(asctime)s] [%(levelname)s] %(message)s"
    console.setFormatter(ColorFormatter(fmt, datefmt="%H:%M:%S"))
    logger.addHandler(console)

    return logger


# Global logger instance
log = setup_logger()
