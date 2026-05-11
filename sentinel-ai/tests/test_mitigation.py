"""
tests/test_mitigation.py
─────────────────────────
Tests for the response engine and mitigation actions.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mitigation.response_engine import (
    MitigationAction,
    MitigationResult,
    MitigationStatus,
    ResponseEngine,
)


class TestResponseEngine:
    def _make_engine(self, dry_run: bool = True) -> ResponseEngine:
        engine = ResponseEngine.__new__(ResponseEngine)
        engine._settings = MagicMock()
        engine._settings.dry_run = dry_run
        engine._settings.alerting.soc_webhook_url = None
        engine._settings.alerting.pagerduty_key = None
        engine._dry_run = dry_run
        engine._alerting = engine._settings.alerting
        engine._history = []
        engine._blocked_ips = set()
        engine._isolated_hosts = set()
        return engine

    # ── do_nothing ────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_do_nothing_skipped(self):
        engine = self._make_engine()
        result = await engine.execute("do_nothing", target="10.0.0.1")
        assert result.status == MitigationStatus.SKIPPED
        assert result.action == MitigationAction.DO_NOTHING

    # ── alert_only ────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_alert_only_dry_run(self):
        engine = self._make_engine(dry_run=True)
        result = await engine.execute("alert_only", target="10.0.0.1", alert_id="alert-001")
        assert result.status == MitigationStatus.DRY_RUN
        assert result.dry_run is True

    # ── block_ip ──────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_block_ip_dry_run(self):
        engine = self._make_engine(dry_run=True)
        result = await engine.execute("block_ip", target="192.168.1.100")
        assert result.status == MitigationStatus.DRY_RUN
        assert "192.168.1.100" in engine.blocked_ips

    @pytest.mark.asyncio
    async def test_block_ip_no_target_fails(self):
        engine = self._make_engine()
        result = await engine.execute("block_ip", target=None)
        assert result.status == MitigationStatus.FAILED
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_block_ip_already_blocked_skips(self):
        engine = self._make_engine()
        engine._blocked_ips.add("10.0.0.1")
        result = await engine.execute("block_ip", target="10.0.0.1")
        assert result.status == MitigationStatus.SKIPPED

    # ── isolate_system ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_isolate_system_dry_run(self):
        engine = self._make_engine(dry_run=True)
        result = await engine.execute("isolate_system", target="webserver01")
        assert result.status == MitigationStatus.DRY_RUN
        assert "webserver01" in engine.isolated_hosts

    @pytest.mark.asyncio
    async def test_isolate_already_isolated_skips(self):
        engine = self._make_engine()
        engine._isolated_hosts.add("webserver01")
        result = await engine.execute("isolate_system", target="webserver01")
        assert result.status == MitigationStatus.SKIPPED

    # ── kill_process ──────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_kill_process_dry_run(self):
        engine = self._make_engine(dry_run=True)
        result = await engine.execute("kill_process", target="webserver01:malware.exe")
        assert result.status == MitigationStatus.DRY_RUN

    # ── escalate_to_human ─────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_escalate_dry_run(self):
        engine = self._make_engine(dry_run=True)
        result = await engine.execute(
            "escalate_to_human",
            target="10.0.0.1",
            alert_id="alert-001",
            context={"threat_type": "ransomware"},
        )
        assert result.status == MitigationStatus.DRY_RUN

    # ── Unknown action ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_unknown_action_fails(self):
        engine = self._make_engine()
        result = await engine.execute("launch_missiles", target="10.0.0.1")
        assert result.status == MitigationStatus.FAILED
        assert "Unknown action" in result.error

    # ── History & metrics ─────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_history_recorded(self):
        engine = self._make_engine()
        await engine.execute("do_nothing")
        await engine.execute("block_ip", target="10.0.0.1")
        history = engine.get_history()
        assert len(history) == 2

    @pytest.mark.asyncio
    async def test_metrics_counts(self):
        engine = self._make_engine()
        await engine.execute("block_ip", target="10.0.0.1")
        await engine.execute("block_ip", target="10.0.0.2")
        await engine.execute("isolate_system", target="host01")
        metrics = engine.get_metrics()
        assert metrics["total_actions"] == 3
        assert metrics["blocked_ips"] == 2
        assert metrics["isolated_hosts"] == 1
        assert metrics["dry_run_mode"] is True

    @pytest.mark.asyncio
    async def test_execution_time_recorded(self):
        engine = self._make_engine()
        result = await engine.execute("do_nothing")
        assert result.execution_time_ms >= 0.0

    def test_result_to_dict(self):
        result = MitigationResult(
            action=MitigationAction.BLOCK_IP,
            status=MitigationStatus.DRY_RUN,
            target="10.0.0.1",
            alert_id="alert-001",
        )
        d = result.to_dict()
        assert d["action"] == "block_ip"
        assert d["status"] == "dry_run"
        assert d["target"] == "10.0.0.1"
