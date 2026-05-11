"""
tests/test_orchestrator.py
───────────────────────────
Tests for the ThreatOrchestrator state machine.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agents.orchestrator import ThreatOrchestrator, ThreatRecord, ThreatState
from detection.anomaly_detector import AnomalyAlert, AlertSeverity


class TestThreatRecord:
    def test_initial_state(self, sample_alert):
        record = ThreatRecord(alert=sample_alert)
        assert record.state == ThreatState.DETECTED
        assert record.threat_id is not None
        assert record.assessment is None
        assert record.mitre_result is None

    def test_update_state(self, sample_alert):
        record = ThreatRecord(alert=sample_alert)
        record.update_state(ThreatState.ANALYSING)
        assert record.state == ThreatState.ANALYSING

    def test_to_dict_contains_required_keys(self, sample_alert):
        record = ThreatRecord(alert=sample_alert)
        d = record.to_dict()
        assert "threat_id" in d
        assert "state" in d
        assert "alert" in d
        assert "created_at" in d
        assert "updated_at" in d

    def test_to_dict_alert_serialised(self, sample_alert):
        record = ThreatRecord(alert=sample_alert)
        d = record.to_dict()
        assert d["alert"]["severity"] == "HIGH"
        assert d["alert"]["composite_score"] == round(sample_alert.composite_score, 4)


class TestThreatOrchestrator:
    def _make_orchestrator(self) -> ThreatOrchestrator:
        """Build an orchestrator with all dependencies mocked."""
        orc = ThreatOrchestrator.__new__(ThreatOrchestrator)
        orc._settings = MagicMock()
        orc._settings.redis.url = "redis://localhost:6379"
        orc._settings.redis.password = None
        orc._settings.redis.db = 0

        orc._pipeline = MagicMock()
        orc._pipeline.start = AsyncMock()
        orc._pipeline.stop = AsyncMock()
        orc._pipeline.stream_events = AsyncMock()
        orc._pipeline.get_metrics = MagicMock(return_value={})

        orc._detector = MagicMock()
        orc._detector.process_batch = MagicMock(return_value=[])
        orc._detector.get_metrics = MagicMock(return_value={})

        orc._analyst = MagicMock()
        orc._analyst.analyse = AsyncMock()

        orc._mitre = MagicMock()
        orc._mitre.match = AsyncMock()

        orc._rl_agent = MagicMock()
        orc._rl_agent.load = MagicMock(return_value=True)
        orc._rl_agent.predict = MagicMock(return_value=("block_ip", 0.85))

        orc._response = MagicMock()
        orc._response.execute = AsyncMock()
        orc._response.get_metrics = MagicMock(return_value={})

        orc._graph = MagicMock()
        orc._graph.connect = AsyncMock()
        orc._graph.close = AsyncMock()
        orc._graph.add_alert_node = AsyncMock()
        orc._graph.upsert_technique = AsyncMock()
        orc._graph.link_alert_to_technique = AsyncMock()
        orc._graph.add_lateral_movement = AsyncMock()

        orc._redis = AsyncMock()
        orc._redis.ping = AsyncMock(return_value=True)
        orc._redis.hset = AsyncMock()
        orc._redis.publish = AsyncMock()
        orc._redis.aclose = AsyncMock()

        orc._running = False
        orc._tasks = []
        orc._threat_records = {}
        orc._metrics = {
            "threats_detected": 0,
            "threats_mitigated": 0,
            "threats_escalated": 0,
            "total_events_processed": 0,
            "start_time": None,
        }
        return orc

    @pytest.mark.asyncio
    async def test_handle_alert_creates_threat_record(self, sample_alert):
        orc = self._make_orchestrator()

        # Mock analyst and mitre responses
        from agents.analyst_agent import ThreatAssessment
        from agents.mitre_matcher import MitreMatchResult
        from mitigation.response_engine import MitigationResult, MitigationAction, MitigationStatus

        assessment = ThreatAssessment(
            threat_type="brute_force",
            confidence=0.85,
            affected_systems=["webserver01"],
            attack_stage="exploitation",
            recommended_actions=["Block IP"],
            urgency="high",
            summary="Brute force detected.",
            raw_analysis="Multiple failed attempts.",
        )
        orc._analyst.analyse = AsyncMock(return_value=assessment)

        mitre_result = MitreMatchResult(
            matches=[],
            attack_chain=[],
            tactics_observed=[],
            overall_confidence=0.7,
            summary="T1110 matched.",
        )
        orc._mitre.match = AsyncMock(return_value=mitre_result)

        mitigation = MitigationResult(
            action=MitigationAction.BLOCK_IP,
            status=MitigationStatus.DRY_RUN,
        )
        orc._response.execute = AsyncMock(return_value=mitigation)

        await orc._handle_alert(sample_alert)

        assert len(orc._threat_records) == 1
        record = list(orc._threat_records.values())[0]
        assert record.alert == sample_alert
        assert record.assessment == assessment
        assert record.rl_action == "block_ip"

    @pytest.mark.asyncio
    async def test_handle_alert_escalates_on_llm_failure(self, sample_alert):
        orc = self._make_orchestrator()
        orc._analyst.analyse = AsyncMock(side_effect=Exception("LLM timeout"))

        await orc._handle_alert(sample_alert)

        record = list(orc._threat_records.values())[0]
        assert record.state == ThreatState.ESCALATED

    @pytest.mark.asyncio
    async def test_process_event_calls_detector(self):
        orc = self._make_orchestrator()
        event = {"event_type": "authentication", "severity": "WARNING"}
        orc._detector.process_batch = MagicMock(return_value=[])
        await orc._process_event(event)
        orc._detector.process_batch.assert_called_once_with([event])

    @pytest.mark.asyncio
    async def test_process_event_spawns_task_on_alert(self, sample_alert):
        orc = self._make_orchestrator()
        orc._detector.process_batch = MagicMock(return_value=[sample_alert])
        orc._metrics["threats_detected"] = 0

        # Patch _handle_alert to avoid full pipeline
        orc._handle_alert = AsyncMock()

        await orc._process_event({"event_type": "test"})
        assert orc._metrics["threats_detected"] == 1

    def test_get_active_threats_excludes_closed(self, sample_alert):
        orc = self._make_orchestrator()

        open_record = ThreatRecord(alert=sample_alert)
        open_record.update_state(ThreatState.CONTAINED)

        closed_record = ThreatRecord(alert=sample_alert)
        closed_record.update_state(ThreatState.CLOSED)

        orc._threat_records = {
            open_record.threat_id: open_record,
            closed_record.threat_id: closed_record,
        }

        active = orc.get_active_threats()
        assert len(active) == 1
        assert active[0]["state"] == "contained"

    def test_get_threat_by_id(self, sample_alert):
        orc = self._make_orchestrator()
        record = ThreatRecord(alert=sample_alert)
        orc._threat_records[record.threat_id] = record

        result = orc.get_threat(record.threat_id)
        assert result is not None
        assert result["threat_id"] == record.threat_id

    def test_get_threat_not_found(self):
        orc = self._make_orchestrator()
        result = orc.get_threat("nonexistent-id")
        assert result is None

    def test_get_metrics_structure(self):
        import time
        orc = self._make_orchestrator()
        orc._metrics["start_time"] = time.monotonic()
        metrics = orc.get_metrics()
        assert "threats_detected" in metrics
        assert "uptime_seconds" in metrics
        assert "active_threats" in metrics
        assert "total_threats" in metrics

    @pytest.mark.asyncio
    async def test_trigger_mitigation_not_found(self):
        orc = self._make_orchestrator()
        result = await orc.trigger_mitigation("nonexistent-alert", "block_ip")
        assert result is None

    @pytest.mark.asyncio
    async def test_trigger_mitigation_found(self, sample_alert):
        from mitigation.response_engine import MitigationResult, MitigationAction, MitigationStatus
        orc = self._make_orchestrator()

        record = ThreatRecord(alert=sample_alert)
        orc._threat_records[record.threat_id] = record

        mock_result = MitigationResult(
            action=MitigationAction.BLOCK_IP,
            status=MitigationStatus.DRY_RUN,
        )
        orc._response.execute = AsyncMock(return_value=mock_result)
        orc._response._dry_run = True

        result = await orc.trigger_mitigation(
            alert_id=sample_alert.alert_id,
            action="block_ip",
            dry_run=True,
        )
        assert result is not None
        assert result.action == MitigationAction.BLOCK_IP
