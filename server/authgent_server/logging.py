"""Structured logging configuration — structlog processor chain with secret redaction."""

from __future__ import annotations

import logging
import re
import sys

import structlog

_REDACT_PATTERNS = [
    re.compile(
        r"(client_secret|secret_key|password|token|authorization|cookie)=([^\s&]+)",
        re.IGNORECASE,
    ),
    re.compile(r"(Bearer|DPoP|Basic)\s+[A-Za-z0-9\-_.~+/]+=*", re.IGNORECASE),
]

_NEVER_LOG_KEYS = frozenset(
    {
        "client_secret",
        "client_secret_hash",
        "previous_secret_hash",
        "secret_key",
        "private_key_pem",
        "password",
        "code_verifier",
        "refresh_token",
        "access_token",
        "subject_token",
        "actor_token",
        "authorization",
    }
)


def _redact_sensitive_values(logger: object, method_name: str, event_dict: dict) -> dict:
    """Processor that redacts sensitive keys from log events."""
    for key in list(event_dict.keys()):
        if key in _NEVER_LOG_KEYS:
            event_dict[key] = "**REDACTED**"
        elif isinstance(event_dict[key], str):
            val = event_dict[key]
            for pattern in _REDACT_PATTERNS:
                val = pattern.sub(r"\1=**REDACTED**", val)
            event_dict[key] = val
    return event_dict


def _add_log_level(logger: object, method_name: str, event_dict: dict) -> dict:
    """Add log level to event dict for JSON output."""
    event_dict["level"] = method_name
    return event_dict


def configure_logging(*, debug: bool = False, json_output: bool = True) -> None:
    """Configure structlog with the authgent processor chain.

    Args:
        debug: Enable DEBUG level logging.
        json_output: Use JSON renderer (True for prod, False for dev console).
    """
    log_level = logging.DEBUG if debug else logging.INFO

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        _add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _redact_sensitive_values,
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Suppress noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO if debug else logging.WARNING)
