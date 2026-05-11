"""
tests/conftest.py
──────────────────
Shared pytest fixtures for the Sentinel AI test suite.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from config.settings import get_settings
from detection.anomaly_detector import AnomalyAlert, AlertSeverity


# ── Event loop ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Settings ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def settings():
    return get_settings()


# ── Sample data ───────────────────────────────────────────────────

@pytest.fixture
def sample_log() -> Dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "event_type": "authentication",
        "raw_message": "Failed password for admin from 192.168.1.100 port 22 ssh2",
        "severity": "WARNING",
        "index": "sentinel-auth",
        "host": "webserver01",
        "user": "admin",
        "process": "sshd",
        "extra": {},
    }


@pytest.fixture
def sample_log_batch(sample_log) -> List[Dict[str, Any]]:
    """A batch of 20 varied log events."""
    batch = []
    severities = ["INFO", "WARNING", "ERROR", "CRITICAL"]
    event_types = ["authentication", "network", "process_execution", "file", "dns"]
    ips = ["192.168.1.100", "10.0.0.5", "172.16.0.20", "203.0.113.10"]

    for i in range(20):
        log = dict(sample_log)
        log["severity"] = severities[i % len(severities)]
        log["event_type"] = event_types[i % len(event_types)]
        log["source_ip"] = ips[i % len(ips)]
        log["raw_message"] = f"Test event {i}: {log['event_type']} from {log['source_ip']}"
        log["is_anomalous"] = i % 5 == 0
        batch.append(log)
    return batch


@pytest.fixture
def sample_alert() -> AnomalyAlert:
    return AnomalyAlert(
        severity=AlertSeverity.HIGH,
        composite_score=0.82,
        vit_score=0.78,
        isolation_score=0.85,
        zscore=2.4,
        anomaly_class="BRUTE_FORCE",
        source_ip="192.168.1.100",
        affected_hosts=["webserver01", "dbserver01"],
        event_count=50,
        raw_logs=[],
        description="Brute force attack detected from 192.168.1.100",
        confidence=0.82,
    )


@pytest.fixture
def sample_threat_assessment() -> Dict[str, Any]:
    return {
        "threat_type": "brute_force",
        "confidence": 0.88,
        "affected_systems": ["webserver01", "192.168.1.100"],
        "attack_stage": "exploitation",
        "recommended_actions": [
            "Block source IP 192.168.1.100",
            "Enable account lockout",
            "Review authentication logs",
        ],
        "threat_actor_profile": "script_kiddie",
        "iocs": ["192.168.1.100"],
        "urgency": "high",
        "summary": "SSH brute force attack detected with 50 failed attempts.",
        "raw_analysis": "High volume of failed SSH authentication attempts from single IP.",
    }


# ── Mock fixtures ─────────────────────────────────────────────────

@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.lpush = AsyncMock(return_value=1)
    redis.brpop = AsyncMock(return_value=("key", '{"test": "event"}'))
    redis.llen = AsyncMock(return_value=0)
    redis.setex = AsyncMock(return_value=True)
    redis.hset = AsyncMock(return_value=True)
    redis.publish = AsyncMock(return_value=1)
    return redis


@pytest.fixture
def mock_es_client():
    """Mock Elasticsearch async client."""
    client = AsyncMock()
    client.info = AsyncMock(return_value={
        "cluster_name": "test-cluster",
        "version": {"number": "8.12.0"},
    })
    client.search = AsyncMock(return_value={
        "hits": {"hits": [], "total": {"value": 0}},
    })
    client.indices.exists = AsyncMock(return_value=True)
    client.indices.create = AsyncMock(return_value={"acknowledged": True})
    return client


@pytest.fixture
def mock_neo4j_driver():
    """Mock Neo4j async driver."""
    driver = AsyncMock()
    session = AsyncMock()
    session.run = AsyncMock()
    driver.session = MagicMock(return_value=session)
    driver.verify_connectivity = AsyncMock()
    return driver


@pytest.fixture
def mock_llm_chain():
    """Mock LangChain chain that returns a valid assessment."""
    chain = AsyncMock()
    chain.ainvoke = AsyncMock(return_value={
        "threat_type": "brute_force",
        "confidence": 0.85,
        "affected_systems": ["webserver01"],
        "attack_stage": "exploitation",
        "recommended_actions": ["Block IP", "Enable MFA"],
        "threat_actor_profile": None,
        "iocs": ["192.168.1.100"],
        "urgency": "high",
        "summary": "Brute force attack detected.",
        "raw_analysis": "Multiple failed auth attempts.",
    })
    return chain
