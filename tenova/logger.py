"""Centralized logging configuration for tenova."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    verbosity: int = 0,
    log_file: Path | None = None,
) -> logging.Logger:
    """Configure the root logger for the migration tool.

    Parameters
    ----------
    verbosity:
        0 = WARNING (default), 1 = INFO, 2+ = DEBUG
    log_file:
        Optional path to a file where logs are also written.

    Returns
    -------
    logging.Logger
        The configured root logger for the package.
    """
    level_map = {0: logging.WARNING, 1: logging.INFO}
    level = level_map.get(verbosity, logging.DEBUG)

    root_logger = logging.getLogger("tenova")
    root_logger.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls
    if not root_logger.handlers:
        # Console handler (stderr)
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(level)
        console.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root_logger.addHandler(console)

        # Optional file handler
        if log_file is not None:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)  # always capture everything to file
            file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
            root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the package namespace."""
    return logging.getLogger(f"tenova.{name}")
