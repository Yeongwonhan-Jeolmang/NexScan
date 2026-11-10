"""
Headless smoke tests for the PyQt6 GUI.

Run with ``QT_QPA_PLATFORM=offscreen`` (set automatically below). Skipped when
PyQt6 (or its system libraries) is not available.
"""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from core.scanner import PortResult, PortState, ScanResult  # noqa: E402


@pytest.fixture()
def window(tmp_path, monkeypatch):
    import gui.app as app_mod

    monkeypatch.setattr(app_mod, "SETTINGS_DIR", str(tmp_path / "cfg"))
    monkeypatch.setattr(app_mod, "SETTINGS_FILE", str(tmp_path / "cfg" / "settings.json"))
    app = app_mod.create_app([])
    win = app_mod.NexScanApp()
    win._set_db_path(str(tmp_path / "history.db"))
    yield win
    win.is_scanning = False
    win.close()
    win.deleteLater()
    app.processEvents()


def _host(target="10.0.0.1"):
    ports = [
        PortResult(
            port=22, protocol="tcp", state=PortState.OPEN, service="ssh", version="OpenSSH 8.9"
        ),
        PortResult(port=80, protocol="tcp", state=PortState.OPEN, service="http"),
        PortResult(port=443, protocol="tcp", state=PortState.FILTERED, service="https"),
        PortResult(port=25, protocol="tcp", state=PortState.CLOSED, service="smtp"),
    ]
    res = ScanResult(target=target, ip_address=target)
    res.ports = ports
    res.host_up = True
    res.open_count, res.filtered_count, res.closed_count = 2, 1, 1
    return res


def _feed(win, res):
    for p in res.ports:
        win._ui_queue.put(("port_found", res.target, p))
    win._ui_queue.put(("host_complete", res))
    win._poll_queue()


def test_window_builds_with_defaults(window):
    assert window._scan_type() == "TCP Connect"
    assert window.sp_threads.value() == 300
    assert window.results_model.rowCount() == 0
    assert window.lbl_empty.isVisibleTo(window.tree.viewport())


def test_live_rows_stats_and_filters(window):
    _feed(window, _host())
    # closed ports hidden by default
    assert window.results_model.rowCount() == 3
    assert window.card_open.get() == 2
    assert window.card_hosts_up.get() == 1

    window.chk_show_closed.setChecked(True)
    window._refresh_results_view()
    assert window.results_model.rowCount() == 4

    window.entry_filter.setText("ssh")
    window._refresh_results_view()
    assert window.results_model.rowCount() == 1

    window.chk_filter_regex.setChecked(True)
    window.entry_filter.setText("^10.*(22|80) ")
    window._refresh_results_view()
    assert window.results_model.rowCount() == 2


def test_header_sort_toggles(window):
    _feed(window, _host())
    window._sort_tree("port")
    assert window.results_model.values_at(0)[1] == 22
    window._sort_tree("port")
    assert window.results_model.values_at(0)[1] == 443


def test_profile_roundtrip(window):
    prof = window._collect_profile()
    prof.update(threads=42, scan_type="UDP", os_detect=True, timeout=2.25)
    window._apply_profile(prof)
    assert window.sp_threads.value() == 42
    assert window._scan_type() == "UDP"
    assert window.chk_os_detect.isChecked()
    cfg = window._get_scan_config()
    assert cfg.threads == 42 and cfg.timeout == pytest.approx(2.25)


def test_history_save_load_diff(window):
    res = _host()
    window.scan_results = [res]
    window._save_current_to_history(quiet=True)
    window._refresh_history()
    assert window.history_tree.topLevelItemCount() == 1
    window.history_tree.topLevelItem(0).setSelected(True)
    window._diff_history_vs_current()
    assert "Run #1" in window.diff_text.toPlainText()
    window._load_history_run()
    assert window.card_open.get() == 2


def test_settings_persist(window, tmp_path):
    import gui.app as app_mod

    window.sp_threads.setValue(77)
    window._save_settings()
    assert os.path.exists(app_mod.SETTINGS_FILE)
    other = app_mod.NexScanApp()
    try:
        assert other.sp_threads.value() == 77
    finally:
        other.close()
