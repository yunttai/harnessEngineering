import re
import threading
import time
from pathlib import Path
from typing import Any
from collections.abc import Callable
from urllib.parse import parse_qsl, unquote, urlsplit

from attack2patch.types.http_log import REDACTED, SENSITIVE_KEYS, HttpLogRecord

ACCESS_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+"
    r"(?P<source_ip>\S+)\s+(?P<status_code>\d{3})$"
)
def parse_access_log_line(line: str) -> HttpLogRecord:
    match = ACCESS_LOG_PATTERN.fullmatch(line.strip())
    if not match:
        raise ValueError("access log line does not match the supported schema")
    target = urlsplit(match.group("target"))
    parameters = {key: value for key, value in parse_qsl(target.query, keep_blank_values=True)}
    return HttpLogRecord(
        timestamp=match.group("timestamp"),
        method=match.group("method"),
        path=unquote(target.path),
        parameters=parameters,
        source_ip=match.group("source_ip"),
        status_code=int(match.group("status_code")),
    )


def parse_access_log_json(line: str) -> HttpLogRecord:
    try:
        return HttpLogRecord.model_validate_json(line)
    except ValueError as exc:
        raise ValueError("access log JSON does not match the supported schema") from exc


def sanitize_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact common secret-bearing keys before logging or storage."""
    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        if SENSITIVE_KEYS.search(key):
            sanitized[key] = REDACTED
        elif isinstance(item, dict):
            sanitized[key] = sanitize_mapping(item)
        else:
            sanitized[key] = item
    return sanitized


class FileLogCollector:
    """Tail newline-delimited, schema-validated JSON records from the demo volume."""

    def __init__(
        self,
        path: Path,
        on_record: Callable[[HttpLogRecord], object],
        poll_interval_seconds: float = 0.2,
    ) -> None:
        self.path = path
        self.on_record = on_record
        self.poll_interval_seconds = poll_interval_seconds
        self._initial_position = path.stat().st_size if path.exists() else 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run,
            name="attack2patch-log-collector",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        position = self._initial_position
        while not self._stop.is_set():
            try:
                if not self.path.exists():
                    time.sleep(self.poll_interval_seconds)
                    continue
                with self.path.open("r", encoding="utf-8") as stream:
                    stream.seek(position)
                    while not self._stop.is_set():
                        line = stream.readline()
                        if not line:
                            position = stream.tell()
                            time.sleep(self.poll_interval_seconds)
                            if self.path.stat().st_size < position:
                                position = 0
                                break
                            continue
                        position = stream.tell()
                        try:
                            self.on_record(parse_access_log_json(line))
                        except (ValueError, OSError):
                            # Malformed/unreadable records are rejected without persisting their content.
                            continue
            except OSError:
                time.sleep(self.poll_interval_seconds)
