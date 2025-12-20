"""Logging configuration setup."""

import logging
import logging.config
from typing import Any

from app.config import get_settings

settings = get_settings()


def setup_logging() -> logging.Logger:
    """Configure logging based on settings."""
    # Determine log format
    if settings.log_format.lower() == "json":
        # JSON format for structured logging
        log_format = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}'
    else:
        # Human-readable text format
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Configure handlers
    handlers: dict[str, Any] = {
        "console": {
            "class": "logging.StreamHandler",
            "level": settings.log_level.upper(),
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        }
    }

    # Add file handler if log file is specified
    if settings.log_file:
        handlers["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": settings.log_level.upper(),
            "formatter": "standard",
            "filename": settings.log_file,
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
        }

    # Logging configuration
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": log_format,
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": handlers,
        "root": {
            "level": settings.log_level.upper(),
            "handlers": list(handlers.keys()),
        },
        "loggers": {
            "uvicorn": {
                "level": settings.uvicorn_log_level.upper(),
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "uvicorn.error": {
                "level": settings.uvicorn_log_level.upper(),
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "uvicorn.access": {
                "level": settings.uvicorn_log_level.upper(),
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "fastapi": {
                "level": settings.fastapi_log_level.upper(),
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
            "fastapi_route_generation": {
                "level": settings.log_level.upper(),
                "handlers": list(handlers.keys()),
                "propagate": False,
            },
        },
    }

    logging.config.dictConfig(logging_config)

    # Get logger for this module
    logger = logging.getLogger("fastapi_route_generation")
    logger.info(
        f"Logging configured: level={settings.log_level}, format={settings.log_format}"
    )
    if settings.log_file:
        logger.info(f"Logging to file: {settings.log_file}")

    return logger
