import logging
import time

ROOT_LOGGER = logging.getLogger("scantron")

# ISO8601 datetime format by default.
LOG_FORMATTER = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s"
)


def log_timestamp():
    """Return a timestamp formatted for logs."""

    now = time.localtime()
    timestamp = time.strftime("%Y%m%d_%H%M%S", now)
    return timestamp
