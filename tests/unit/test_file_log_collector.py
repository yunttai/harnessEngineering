import threading
from datetime import datetime, timezone

from attack2patch.runtime.log_collector import FileLogCollector
from attack2patch.types.http_log import HttpLogRecord


def test_file_collector_emits_only_schema_valid_records(tmp_path):
    path = tmp_path / "access.jsonl"
    path.write_text("", encoding="utf-8")
    received = []
    ready = threading.Event()

    def on_record(record):
        received.append(record)
        ready.set()

    collector = FileLogCollector(path, on_record, poll_interval_seconds=0.01)
    collector.start()
    try:
        with path.open("a", encoding="utf-8") as stream:
            stream.write("not-json\n")
            stream.write(
                HttpLogRecord(
                    timestamp=datetime.now(timezone.utc),
                    method="GET",
                    path="/api/users",
                    parameters={"name": "' OR 1=1--"},
                    source_ip="127.0.0.1",
                    status_code=200,
                ).model_dump_json()
                + "\n"
            )
        assert ready.wait(timeout=2)
    finally:
        collector.stop()
    assert len(received) == 1
    assert received[0].parameters["name"] == "' OR 1=1--"
