from core.support_logger import SupportLogger


def test_support_logger_writes_process_and_error_logs(tmp_path):
    logger = SupportLogger(log_dir=tmp_path)

    logger.process("Import started", slot="USERS", filename="users.csv")

    try:
        raise ValueError("boom")
    except ValueError as exc:
        logger.error("Audit failed", exception=exc, period="2026-Q2")

    process_log = tmp_path / "process.log"
    error_log = tmp_path / "error.log"

    assert process_log.exists()
    assert error_log.exists()

    process_content = process_log.read_text(encoding="utf-8")
    error_content = error_log.read_text(encoding="utf-8")

    assert "Import started" in process_content
    assert 'slot="USERS"' in process_content
    assert 'filename="users.csv"' in process_content

    assert "Audit failed" in error_content
    assert "ValueError" in error_content
    assert "boom" in error_content
    assert 'period="2026-Q2"' in error_content
