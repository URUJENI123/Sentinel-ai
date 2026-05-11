"""
mitigation/response_engine.py
──────────────────────────────
Executes mitigation actions recommended by the RL agent and analyst.
Supports dry-run mode (logs actions without executing) and live mode
(executes via API calls to firewalls, EDR, SIEM).

Actions:
    do_nothing          — No action taken
    alert_only          — Send alert to SOC webhook / PagerDuty
    block_ip            — Add IP to firewall blocklist
    isolate_system      — Quarantine host from network
    kill_process        — Terminate malicious process
    escalate_to_human   — Page on-call analyst
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from config.settings import get_settings


# ── Action types ──────────────────────────────────────────────────

class MitigationAction(str, Enum):
    DO_NOTHING = "do_nothing"
    ALERT_ONLY = "alert_only"
    BLOCK_IP = "block_ip"
    ISOLATE_SYSTEM = "isolate_system"
    KILL_PROCESS = "kill_process"
    ESCALATE_TO_HUMAN = "escalate_to_human"


class MitigationStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"
    DRY_RUN = "dry_run"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Result model ──────────────────────────────────────────────────

@dataclass
class MitigationResult:
    """Result of a mitigation action execution."""

    result_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: MitigationAction = MitigationAction.DO_NOTHING
    status: MitigationStatus = MitigationStatus.PENDING
    target: Optional[str] = None
    alert_id: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    dry_run: bool = True
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "action": self.action.value,
            "status": self.status.value,
            "target": self.target,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "dry_run": self.dry_run,
            "details": self.details,
            "error": self.error,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }


# ── ResponseEngine ────────────────────────────────────────────────

class ResponseEngine:
    """
    Executes mitigation actions with dry-run safety by default.

    In dry_run mode (default): logs all actions without executing them.
    In live mode: executes actions via configured integrations.

    Integrations (live mode):
        - Firewall API (block_ip)
        - EDR API (isolate_system, kill_process)
        - SOC webhook / PagerDuty (alert_only, escalate_to_human)

    Usage::

        engine = ResponseEngine()
        result = await engine.execute(
            action="block_ip",
            target="192.168.1.50",
            alert_id="alert-001",
            context={"reason": "Port scan detected"}
        )
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._dry_run = self._settings.dry_run
        self._alerting = self._settings.alerting
        self._history: List[MitigationResult] = []
        self._blocked_ips: set = set()
        self._isolated_hosts: set = set()

        if self._dry_run:
            logger.info("ResponseEngine initialised in DRY-RUN mode — no actions will be executed")
        else:
            logger.warning("ResponseEngine initialised in LIVE mode — actions WILL be executed")

    # ── Main dispatch ─────────────────────────────────────────────

    async def execute(
        self,
        action: str,
        target: Optional[str] = None,
        alert_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> MitigationResult:
        """
        Execute a mitigation action.

        Args:
            action:   Action name (matches MitigationAction enum values)
            target:   IP address, hostname, or process ID
            alert_id: Associated alert ID for audit trail
            context:  Additional context (threat type, confidence, etc.)

        Returns:
            MitigationResult with execution status and details
        """
        import time
        start = time.monotonic()

        try:
            action_enum = MitigationAction(action)
        except ValueError:
            logger.error("Unknown mitigation action: {}", action)
            result = MitigationResult(
                action=MitigationAction.DO_NOTHING,
                status=MitigationStatus.FAILED,
                target=target,
                alert_id=alert_id,
                error=f"Unknown action: {action}",
            )
            self._history.append(result)
            return result

        result = MitigationResult(
            action=action_enum,
            target=target,
            alert_id=alert_id,
            dry_run=self._dry_run,
            details=context or {},
        )

        logger.info(
            "Executing mitigation: action={} target={} alert={} dry_run={}",
            action, target, alert_id, self._dry_run,
        )

        try:
            dispatch = {
                MitigationAction.DO_NOTHING: self._do_nothing,
                MitigationAction.ALERT_ONLY: self._alert_only,
                MitigationAction.BLOCK_IP: self._block_ip,
                MitigationAction.ISOLATE_SYSTEM: self._isolate_system,
                MitigationAction.KILL_PROCESS: self._kill_process,
                MitigationAction.ESCALATE_TO_HUMAN: self._escalate_to_human,
            }
            handler = dispatch[action_enum]
            await handler(result)

        except Exception as exc:
            result.status = MitigationStatus.FAILED
            result.error = str(exc)
            logger.error("Mitigation action failed: {} — {}", action, exc)

        import time
        result.execution_time_ms = (time.monotonic() - start) * 1000
        self._history.append(result)

        logger.info(
            "Mitigation complete: action={} status={} target={} time={:.1f}ms",
            action, result.status.value, target, result.execution_time_ms,
        )
        return result

    # ── Action handlers ───────────────────────────────────────────

    async def _do_nothing(self, result: MitigationResult) -> None:
        result.status = MitigationStatus.SKIPPED
        result.details["reason"] = "Action: do_nothing — no response taken"

    async def _alert_only(self, result: MitigationResult) -> None:
        """Send alert to SOC webhook."""
        payload = {
            "alert_id": result.alert_id,
            "action": "alert_only",
            "target": result.target,
            "timestamp": result.timestamp,
            "details": result.details,
            "source": "Sentinel AI",
        }

        if self._dry_run:
            logger.info("[DRY-RUN] Would send SOC alert: {}", json.dumps(payload))
            result.status = MitigationStatus.DRY_RUN
            return

        await self._send_webhook(payload)
        result.status = MitigationStatus.EXECUTED

    async def _block_ip(self, result: MitigationResult) -> None:
        """Add IP to firewall blocklist."""
        ip = result.target
        if not ip:
            result.status = MitigationStatus.FAILED
            result.error = "No target IP provided for block_ip action"
            return

        if ip in self._blocked_ips:
            result.status = MitigationStatus.SKIPPED
            result.details["reason"] = f"IP {ip} already blocked"
            return

        if self._dry_run:
            logger.warning("[DRY-RUN] Would block IP: {}", ip)
            result.status = MitigationStatus.DRY_RUN
            result.details["firewall_rule"] = f"DENY ALL FROM {ip}"
            self._blocked_ips.add(ip)
            return

        # Live: call firewall API
        await self._call_firewall_api("block", ip)
        self._blocked_ips.add(ip)
        result.status = MitigationStatus.EXECUTED
        result.details["firewall_rule"] = f"DENY ALL FROM {ip}"
        logger.warning("IP BLOCKED: {}", ip)

    async def _isolate_system(self, result: MitigationResult) -> None:
        """Quarantine a host from the network via EDR."""
        host = result.target
        if not host:
            result.status = MitigationStatus.FAILED
            result.error = "No target host provided for isolate_system action"
            return

        if host in self._isolated_hosts:
            result.status = MitigationStatus.SKIPPED
            result.details["reason"] = f"Host {host} already isolated"
            return

        if self._dry_run:
            logger.warning("[DRY-RUN] Would isolate host: {}", host)
            result.status = MitigationStatus.DRY_RUN
            result.details["isolation_policy"] = "FULL_NETWORK_ISOLATION"
            self._isolated_hosts.add(host)
            return

        # Live: call EDR API
        await self._call_edr_api("isolate", host)
        self._isolated_hosts.add(host)
        result.status = MitigationStatus.EXECUTED
        result.details["isolation_policy"] = "FULL_NETWORK_ISOLATION"
        logger.warning("HOST ISOLATED: {}", host)

    async def _kill_process(self, result: MitigationResult) -> None:
        """Terminate a malicious process via EDR."""
        target = result.target  # format: "host:pid" or "host:process_name"

        if self._dry_run:
            logger.warning("[DRY-RUN] Would kill process: {}", target)
            result.status = MitigationStatus.DRY_RUN
            result.details["kill_target"] = target
            return

        await self._call_edr_api("kill_process", target)
        result.status = MitigationStatus.EXECUTED
        logger.warning("PROCESS KILLED: {}", target)

    async def _escalate_to_human(self, result: MitigationResult) -> None:
        """Page the on-call analyst via PagerDuty / webhook."""
        payload = {
            "routing_key": self._alerting.pagerduty_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"CRITICAL: Sentinel AI escalation — {result.details.get('threat_type', 'Unknown threat')}",
                "severity": "critical",
                "source": result.target or "unknown",
                "custom_details": {
                    "alert_id": result.alert_id,
                    "details": result.details,
                    "timestamp": result.timestamp,
                },
            },
        }

        if self._dry_run:
            logger.warning("[DRY-RUN] Would escalate to human: {}", json.dumps(payload, indent=2))
            result.status = MitigationStatus.DRY_RUN
            return

        # PagerDuty
        if self._alerting.pagerduty_key:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                )
                resp.raise_for_status()

        # Webhook fallback
        if self._alerting.soc_webhook_url:
            await self._send_webhook(payload)

        result.status = MitigationStatus.EXECUTED
        logger.warning("ESCALATED TO HUMAN: alert={}", result.alert_id)

    # ── Integration helpers ───────────────────────────────────────

    async def _send_webhook(self, payload: Dict[str, Any]) -> None:
        """Send a JSON payload to the configured SOC webhook."""
        if not self._alerting.soc_webhook_url:
            logger.debug("No SOC webhook configured — skipping notification")
            return
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                self._alerting.soc_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            logger.debug("Webhook delivered: status={}", resp.status_code)

    async def _call_firewall_api(self, operation: str, ip: str) -> None:
        """
        Stub for firewall API integration.
        Replace with your actual firewall vendor API (Palo Alto, Fortinet, etc.)
        """
        logger.info("Firewall API: {} {}", operation, ip)
        # Example: await client.post(f"{FIREWALL_URL}/api/block", json={"ip": ip})
        await asyncio.sleep(0.1)  # simulate API latency

    async def _call_edr_api(self, operation: str, target: str) -> None:
        """
        Stub for EDR API integration.
        Replace with your actual EDR vendor API (CrowdStrike, SentinelOne, etc.)
        """
        logger.info("EDR API: {} {}", operation, target)
        # Example: await client.post(f"{EDR_URL}/api/{operation}", json={"host": target})
        await asyncio.sleep(0.1)  # simulate API latency

    # ── State & metrics ───────────────────────────────────────────

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent mitigation history."""
        return [r.to_dict() for r in self._history[-limit:]]

    def get_metrics(self) -> Dict[str, Any]:
        """Return mitigation statistics."""
        total = len(self._history)
        by_action: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for r in self._history:
            by_action[r.action.value] = by_action.get(r.action.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1

        return {
            "total_actions": total,
            "blocked_ips": len(self._blocked_ips),
            "isolated_hosts": len(self._isolated_hosts),
            "dry_run_mode": self._dry_run,
            "by_action": by_action,
            "by_status": by_status,
        }

    @property
    def blocked_ips(self) -> List[str]:
        return list(self._blocked_ips)

    @property
    def isolated_hosts(self) -> List[str]:
        return list(self._isolated_hosts)
