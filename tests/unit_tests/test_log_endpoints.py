import logging
from logging.handlers import RotatingFileHandler

from volttron.services.web.vui_endpoints import (
    _available_log_files,
    _read_log_file,
)


def test_log_discovery_and_bounded_reads(tmp_path, monkeypatch):
    active = tmp_path / "volttron.log"
    rotated = tmp_path / "volttron.log.1"
    active.write_bytes(b"one\ntwo\nthree\n")
    rotated.write_bytes(b"old\n")
    handler = logging.FileHandler(active)
    monkeypatch.setattr(logging.getLogger(), "handlers", [handler])

    discovered = _available_log_files()
    assert [item["id"] for item in discovered] == ["volttron.log", "volttron.log.1"]

    tail = _read_log_file("volttron.log", tail=2, offset=None, before=None, max_bytes=64)
    assert tail["lines"] == ["two", "three"]
    assert tail["next_offset"] == active.stat().st_size
    assert tail["file_id"]

    chunk = _read_log_file("volttron.log", tail=200, offset=0, before=None, max_bytes=5)
    assert chunk["lines"] == ["one"]
    assert chunk["next_offset"] == 4

    handler.close()


def test_log_retention_reports_rotating_handler_limits(tmp_path, monkeypatch):
    from volttron.services.web.vui_endpoints import _log_retention

    handler = RotatingFileHandler(tmp_path / "volttron.log", maxBytes=10 * 1024 * 1024, backupCount=5)
    monkeypatch.setattr(logging.getLogger(), "handlers", [handler])
    assert _log_retention() == {
        "max_file_bytes": 10 * 1024 * 1024,
        "backup_count": 5,
        "max_total_bytes": 60 * 1024 * 1024,
    }
    handler.close()


def test_log_reader_rejects_unknown_files(tmp_path, monkeypatch):
    active = tmp_path / "volttron.log"
    active.write_text("one\n")
    handler = logging.FileHandler(active)
    monkeypatch.setattr(logging.getLogger(), "handlers", [handler])

    try:
        _read_log_file("../secrets", tail=1, offset=None, before=None, max_bytes=64)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("arbitrary log path was accepted")
    finally:
        handler.close()


def test_log_reader_pages_backward_on_complete_lines(tmp_path, monkeypatch):
    active = tmp_path / "volttron.log"
    active.write_bytes(b"one\ntwo\nthree\nfour\n")
    handler = logging.FileHandler(active)
    monkeypatch.setattr(logging.getLogger(), "handlers", [handler])

    newest = _read_log_file("volttron.log", tail=200, offset=None, before=active.stat().st_size, max_bytes=11)
    assert newest["lines"] == ["two", "three", "four"]
    assert newest["start_offset"] == len(b"one\n")
    assert newest["end_offset"] == active.stat().st_size
    assert newest["previous_offset"] == len(b"one\n")
    assert newest["has_older"] is True
    assert newest["file_id"]

    older = _read_log_file("volttron.log", tail=200, offset=None, before=newest["previous_offset"], max_bytes=11)
    assert older["lines"] == ["one"]
    assert older["start_offset"] == 0
    assert older["previous_offset"] == 0
    assert older["has_older"] is False
    handler.close()
