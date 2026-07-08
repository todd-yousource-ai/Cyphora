from __future__ import annotations

import logging
import os

import structlog


_CONFIGURED = False
_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def _resolve_level(value: str | None) -> int:
    if not value:
        return logging.INFO
    return _LEVELS.get(value.strip().upper(), logging.INFO)


def configure_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    level = _resolve_level(os.getenv("LOG_LEVEL"))

    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _CONFIGURED = True
