"""
agents/orchestrator.py
───────────────────────
ThreatOrchestrator — the central state machine that coordinates all
agents and components in the Sentinel AI pipeline.

Flow:
    AnomalyAlert
        → AnalystAgent (LLM threat assessment)
        → MitreMatcher (ATT&CK technique mapping)
        → AttackGraph (Neo4j graph update)
        → RLMitigationAgent (action decision)
        → ResponseEngine (action execution)
        → SOC notification
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from loguru import logger

from agents.analyst_agent import AnalystAgent, ThreatAssessment
from agents.mitre_matcher import MitreMatcher, MitreMatchResult
from agents.rl_agent import RLMitigationAgent
from config.settings import get_settings
from detection.anomaly_detector import AnomalyAlert, AnomalyDetector
from graph.attack_graph import AttackGraph
from ingestion.pipeline import IngestionPipeline
from mitigation.response_engine import MitigationResult, ResponseEngine


# ── Threat state machine ──────────────────────────────────────────

class ThreatState(str, Enum):
    DETECTED = "detected"
    ANALYSING = "analysing"
    MITRE_MATCHED = "mitre_matched"
    MITIGATING = "mitigating"
    CONTAINED = "contained"
    ESCALATED = "escalated"
    CLOSED = "closed"


@dataclass
class ThreatRecord:
    """Full lifecycle record for a detected threat."""

    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: ThreatState = ThreatState.DETECTED
    alert: Optional[AnomalyAlert] = None
    assessment: Optional[ThreatAssessment] = None
    mitre_result: Optional[MitreMatchResult] = None
    mitigation_result: Optional[MitigationResult] = None
    rl_action: Optional[str] = None
    rl_confidence: float = 0.0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    processing_time_ms: float = 0.0

    def update_state(self, new_state: ThreatState) -> None:
        self.state = new_state
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "state": self.state.value,
            "alert": self.alert.to_dict() if self.alert else None,
            "assessment": self.assessment.model_dump() if self.assessment else None,
            "mitre_result": self.mitre_result.model_dump() if self.mitre_result else None,
            "mitigation_result": self.mitigation_result.to_dict() if self.mitigation_result else None,
            "rl_action": self.rl_action,
            "rl_confidence": round(self.rl_confidence, 3),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }


# ── ThreatOrchestrator ────────────────────────────────────────────

class ThreatOrchestrator:
    """
    Central coordinator for the Sentinel AI threat response pipeline.

    Manages the full lifecycle from anomaly detection to mitigation,
    coordinating all agents and maintaining threat state.

    Usage::

        orchestrator = ThreatOrchestrator()
        await orchestrator.start()
        # Runs autonomously until stopped
        await orchestrator.stop()
    """

    THREAT_RECORD_KEY = "sentinel:threats"
    ALERT_CHANNEL = "sentinel:alerts"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._pipeline = IngestionPipeline()
        self._detector = AnomalyDetector()
        self._analyst = AnalystAgent()
        self._mitre = MitreMatcher()
        self._rl_agent = RLMitigationAgent()
        self._response = ResponseEngine()
        self._graph = AttackGraph()
        self._redis: Optional[aioredis.Redis] = None
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._threat_records: Dict[str, ThreatRecord] = {}
        self._metrics = {
            "threats_detected": 0,
            "threats_mitigated": 0,
            "threats_escalated": 0,
            "total_events_processed": 0,
            "start_time": None,
        }

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the full Sentinel AI pipeline."""
        logger.info("Starting ThreatOrchestrator...")
        self._metrics["start_time"] = time.monotonic()

        # Connect infrastructure
        await self._pipeline.start()
        await self._graph.connect()
        await self._connect_redis()

        # Load RL model
        self._rl_agent.load()

        self._running = True

        # Launch processing tasks
        self._tasks = [
            asyncio.create_task(self._run_detection_loop(), name="detection-loop"),
            asyncio.create_task(self._run_alert_publisher(), name="alert-publisher"),
        ]

        logger.info("ThreatOrchestrator started — autonomous threat hunting active")

    async def stop(self) -> None:
        """Gracefully stop all components."""
        logger.info("Stopping ThreatOrchestrator...")
        self._running = False

        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

        await self._pipeline.stop()
        await self._graph.close()
        if self._redis:
            await self._redis.aclose()

        logger.info("ThreatOrchestrator stopped. Final metrics: {}", self.get_metrics())

    async def _connect_redis(self) -> None:
        cfg = self._settings.redis
        self._redis = aioredis.from_url(
            cfg.url,
            password=cfg.password or None,
            db=cfg.db,
            decode_responses=True,
        )
        await self._redis.ping()
        logger.info("Orchestrator connected to Redis")

    # ── Detection loop ────────────────────────────────────────────

    async def _run_detection_loop(self) -> None:
        """Main loop: consume events → detect → respond."""
        logger.info("Detection loop started")
        async for event in self._pipeline.stream_events():
            if not self._running:
                break
            try:
                self._metrics["total_events_processed"] += 1
                await self._process_event(event)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Detection loop error: {}", exc)

    async def _process_event(self, event: Dict[str, Any]) -> None:
        """Process a single event through the detection pipeline."""
        alerts = self._detector.process_batch([event])
        for alert in alerts:
            self._metrics["threats_detected"] += 1
            asyncio.create_task(self._handle_alert(alert))

    # ── Alert handling ────────────────────────────────────────────

    async def _handle_alert(self, alert: AnomalyAlert) -> None:
        """
        Full alert handling pipeline:
        1. Create threat record
        2. LLM analysis
        3. MITRE matching
        4. Graph update
        5. RL decision
        6. Execute mitigation
        """
        start = time.monotonic()
        record = ThreatRecord(alert=alert)
        self._threat_records[record.threat_id] = record

        logger.info(
            "Handling alert: id={} severity={} score={:.3f}",
            alert.alert_id, alert.severity.value, alert.composite_score,
        )

        try:
            # Step 1: LLM analysis
            record.update_state(ThreatState.ANALYSING)
            assessment = await self._analyst.analyse(alert)
            record.assessment = assessment

            # Step 2: MITRE matching
            mitre_result = await self._mitre.match(
                assessment.model_dump(),
                log_context=alert.raw_logs,
            )
            record.mitre_result = mitre_result
            record.update_state(ThreatState.MITRE_MATCHED)

            # Step 3: Update attack graph
            await self._update_graph(alert, assessment, mitre_result)

            # Step 4: RL decision
            rl_state = {
                "anomaly_score": alert.composite_score,
                "threat_type": assessment.threat_type,
                "affected_systems_count": len(assessment.affected_systems),
                "attack_stage": assessment.attack_stage,
                "time_since_detection": 0.0,
            }
            action, confidence = self._rl_agent.predict(rl_state)
            record.rl_action = action
            record.rl_confidence = confidence

            logger.info(
                "RL decision: action={} confidence={:.2f} threat={}",
                action, confidence, assessment.threat_type,
            )

            # Step 5: Execute mitigation
            record.update_state(ThreatState.MITIGATING)
            mitigation_result = await self._response.execute(
                action=action,
                target=alert.source_ip,
                alert_id=alert.alert_id,
                context={
                    "threat_type": assessment.threat_type,
                    "confidence": assessment.confidence,
                    "urgency": assessment.urgency,
                    "attack_stage": assessment.attack_stage,
                    "rl_confidence": confidence,
                    "mitre_techniques": [m.technique_id for m in mitre_result.matches],
                },
            )
            record.mitigation_result = mitigation_result

            # Update state
            if action == "escalate_to_human":
                record.update_state(ThreatState.ESCALATED)
                self._metrics["threats_escalated"] += 1
            elif action in ("block_ip", "isolate_system", "kill_process"):
                record.update_state(ThreatState.CONTAINED)
                self._metrics["threats_mitigated"] += 1
            else:
                record.update_state(ThreatState.CLOSED)

        except Exception as exc:
            logger.error("Alert handling failed for {}: {}", alert.alert_id, exc)
            record.update_state(ThreatState.ESCALATED)

        finally:
            record.processing_time_ms = (time.monotonic() - start) * 1000
            # Persist to Redis
            await self._persist_threat_record(record)

    async def _update_graph(
        self,
        alert: AnomalyAlert,
        assessment: ThreatAssessment,
        mitre_result: MitreMatchResult,
    ) -> None:
        """Update the Neo4j attack graph with new threat data."""
        try:
            # Add alert node
            await self._graph.add_alert_node(alert.to_dict())

            # Add technique nodes and link
            for match in mitre_result.matches:
                await self._graph.upsert_technique(
                    match.technique_id,
                    match.technique_name,
                    match.tactic,
                )
                await self._graph.link_alert_to_technique(
                    alert.alert_id,
                    match.technique_id,
                    match.confidence,
                )

            # Record lateral movement if detected
            if (
                assessment.attack_stage == "lateral_movement"
                and alert.source_ip
                and len(alert.affected_hosts) > 0
            ):
                for dst_host in alert.affected_hosts:
                    await self._graph.add_lateral_movement(
                        src_ip=alert.source_ip,
                        dst_ip=dst_host,
                        technique_id=mitre_result.attack_chain[0] if mitre_result.attack_chain else None,
                        confidence=assessment.confidence,
                    )

        except Exception as exc:
            logger.warning("Graph update failed: {}", exc)

    # ── Alert publishing ──────────────────────────────────────────

    async def _run_alert_publisher(self) -> None:
        """Publish high-severity alerts to Redis pub/sub channel."""
        logger.info("Alert publisher started")
        while self._running:
            try:
                await asyncio.sleep(1)
                # Publish any new CRITICAL/HIGH threats
                for record in list(self._threat_records.values()):
                    if (
                        record.alert
                        and record.alert.severity.value in ("CRITICAL", "HIGH")
                        and record.state in (ThreatState.CONTAINED, ThreatState.ESCALATED)
                        and self._redis
                    ):
                        import json
                        await self._redis.publish(
                            self.ALERT_CHANNEL,
                            json.dumps(record.to_dict(), default=str),
                        )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Alert publisher error: {}", exc)

    async def _persist_threat_record(self, record: ThreatRecord) -> None:
        """Persist a threat record to Redis."""
        if not self._redis:
            return
        try:
            import json
            await self._redis.hset(
                self.THREAT_RECORD_KEY,
                record.threat_id,
                json.dumps(record.to_dict(), default=str),
            )
        except Exception as exc:
            logger.debug("Failed to persist threat record: {}", exc)

    # ── Manual trigger ────────────────────────────────────────────

    async def process_alert_directly(self, alert: AnomalyAlert) -> ThreatRecord:
        """
        Manually inject an alert for processing (used by API endpoints).
        Returns the completed ThreatRecord.
        """
        record = ThreatRecord(alert=alert)
        self._threat_records[record.threat_id] = record
        await self._handle_alert(alert)
        return self._threat_records[record.threat_id]

    async def trigger_mitigation(
        self,
        alert_id: str,
        action: str,
        dry_run: bool = True,
    ) -> Optional[MitigationResult]:
        """Manually trigger a mitigation action for an alert."""
        # Find the threat record
        record = next(
            (r for r in self._threat_records.values()
             if r.alert and r.alert.alert_id == alert_id),
            None,
        )
        if not record:
            logger.warning("Alert {} not found for manual mitigation", alert_id)
            return None

        # Temporarily override dry_run if requested
        original_dry_run = self._response._dry_run
        self._response._dry_run = dry_run

        result = await self._response.execute(
            action=action,
            target=record.alert.source_ip if record.alert else None,
            alert_id=alert_id,
        )

        self._response._dry_run = original_dry_run
        return result

    # ── Queries ───────────────────────────────────────────────────

    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Return threats that are not yet closed."""
        return [
            r.to_dict()
            for r in self._threat_records.values()
            if r.state not in (ThreatState.CLOSED,)
        ]

    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific threat record by ID."""
        record = self._threat_records.get(threat_id)
        return record.to_dict() if record else None

    def get_metrics(self) -> Dict[str, Any]:
        uptime = (
            time.monotonic() - self._metrics["start_time"]
            if self._metrics["start_time"]
            else 0
        )
        return {
            **self._metrics,
            "uptime_seconds": round(uptime, 2),
            "active_threats": len([
                r for r in self._threat_records.values()
                if r.state not in (ThreatState.CLOSED,)
            ]),
            "total_threats": len(self._threat_records),
            "pipeline_metrics": self._pipeline.get_metrics(),
            "detection_metrics": self._detector.get_metrics(),
            "mitigation_metrics": self._response.get_metrics(),
        }
