"""Unit tests for the ``python -m web_auth_bridge`` entry point.

The module is thin — it configures logging and dispatches to :mod:`cli`.
These tests assert on the observable exit behavior and the failure-path
wrapping of :class:`WebAuthBridgeError`.
"""

from __future__ import annotations

import pytest

from web_auth_bridge import __main__ as entry
from web_auth_bridge.exceptions import WebAuthBridgeError


class TestMainEntryPoint:
    def test_exits_with_cli_return_code_on_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The return value of ``cli_main`` must propagate via ``sys.exit``."""
        monkeypatch.setattr(entry, "cli_main", lambda: 0)

        with pytest.raises(SystemExit) as excinfo:
            entry.main()

        assert excinfo.value.code == 0, f"main() must exit with cli_main's return code (0), got {excinfo.value.code}"

    def test_exits_with_one_on_web_auth_bridge_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def _explode() -> int:
            raise WebAuthBridgeError("kaboom")

        monkeypatch.setattr(entry, "cli_main", _explode)

        with caplog.at_level("ERROR", logger="web_auth_bridge.__main__"), pytest.raises(SystemExit) as excinfo:
            entry.main()

        assert excinfo.value.code == 1, f"WebAuthBridgeError must result in exit code 1, got {excinfo.value.code}"
        assert any("kaboom" in record.getMessage() for record in caplog.records), (
            f"Error message 'kaboom' must be logged at ERROR level; got records: "
            f"{[r.getMessage() for r in caplog.records]}"
        )

    def test_does_not_catch_unexpected_exceptions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only ``WebAuthBridgeError`` is caught — generic errors should crash with a traceback."""

        def _unexpected() -> int:
            raise RuntimeError("unexpected")

        monkeypatch.setattr(entry, "cli_main", _unexpected)

        with pytest.raises(RuntimeError, match="unexpected"):
            entry.main()
