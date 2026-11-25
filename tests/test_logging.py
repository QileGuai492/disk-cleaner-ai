"""日志与审计测试。"""

import json

from disk_cleaner.logging_utils import audit, get_logger, setup_logging


def test_file_log_and_audit(tmp_path):
    logger = setup_logging(log_dir=str(tmp_path), level="DEBUG")
    logger.info("hello-log")
    get_logger("test").warning("child-log")
    audit("test_event", path="C:\\example", count=2)

    for handler in logger.handlers:
        handler.flush()

    log_text = (tmp_path / "disk-cleaner.log").read_text(encoding="utf-8")
    assert "hello-log" in log_text
    assert "child-log" in log_text

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    record = json.loads(audit_text)
    assert record["event"] == "test_event"
    assert record["path"] == "C:\\example"
    assert record["count"] == 2

    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
