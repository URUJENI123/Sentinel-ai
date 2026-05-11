"""
tests/test_api.py
──────────────────
Tests for the FastAPI REST and WebSocket endpoints.
Uses TestClient (sync) and AsyncClient (async) from httpx.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# We patch the lifespan so no real infrastructure is needed
import api.main as api_module


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def mock_orchestrator():
    orc = MagicMock()
    orc.get_metrics.return_value = {
        "uptime_seconds": 42.0,
        "threats_detected": 5,
        "threats_mitigated": 3,
        "threats_escalated": 1,
        "total_events_processed": 1000,
        "active_threats": 2,
        "total_threats": 5,
        "pipeline_metrics": {},
        "detection_metrics": {},
        "mitigation_metrics": {},
    }
    orc.get_active_threats.return_value = [
        {
            "threat_id": "threat-001",
            "state": "contained",
            "alert": {
                "alert_id": "alert-001",
                "severity": "HIGH",
                "composite_score": 0.85,
            },
        }
    ]
    orc.get_threat.return_value = {
        "threat_id": "threat-001",
        "state": "contained",
    }
    orc.trigger_mitigation = AsyncMock(return_value=MagicMock(
        to_dict=lambda: {
            "result_id": "result-001",
            "action": "block_ip",
            "status": "dry_run",
        }
    ))
    orc._graph = MagicMock()
    orc._graph.get_attack_path = AsyncMock(return_value=[])
    orc._graph.get_blast_radius = AsyncMock(return_value={"host_ip": "10.0.0.1", "reachable_hosts": 2})
    orc._graph.get_compromised_hosts = AsyncMock(return_value=[])
    orc._graph.get_technique_frequency = AsyncMock(return_value=[])
    orc._process_event = AsyncMock()
    return orc


@pytest.fixture
def mock_simulator():
    sim = MagicMock()
    sim.list_scenarios.return_value = [
        {"name": "brute_force_ssh", "description": "SSH brute force", "severity": "HIGH"}
    ]
    sim.get_active_simulations.return_value = []
    sim.stop_simulation.return_value = True
    return sim


@pytest.fixture
def client(mock_orchestrator, mock_simulator):
    """TestClient with mocked orchestrator and simulator."""
    api_module.orchestrator = mock_orchestrator
    api_module.simulator = mock_simulator
    from api.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_response_schema(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "status" in data
        assert "version" in data
        assert "uptime_seconds" in data
        assert "components" in data

    def test_health_status_healthy(self, client):
        resp = client.get("/health")
        assert resp.json()["status"] == "healthy"

    def test_health_503_when_no_orchestrator(self, mock_simulator):
        api_module.orchestrator = None
        from api.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            resp = c.get("/health")
        assert resp.status_code == 503
        api_module.orchestrator = MagicMock()  # restore


# ── Metrics ───────────────────────────────────────────────────────

class TestMetrics:
    def test_metrics_returns_200(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_contains_expected_keys(self, client):
        resp = client.get("/metrics")
        data = resp.json()
        assert "uptime_seconds" in data
        assert "threats_detected" in data


# ── Threats ───────────────────────────────────────────────────────

class TestThreats:
    def test_get_active_threats(self, client):
        resp = client.get("/threats/active")
        assert resp.status_code == 200
        data = resp.json()
        assert "threats" in data
        assert isinstance(data["threats"], list)

    def test_get_threat_by_id(self, client):
        resp = client.get("/threats/threat-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["threat_id"] == "threat-001"

    def test_get_threat_not_found(self, client, mock_orchestrator):
        mock_orchestrator.get_threat.return_value = None
        resp = client.get("/threats/nonexistent-id")
        assert resp.status_code == 404

    def test_trigger_mitigation(self, client):
        resp = client.post(
            "/threats/alert-001/mitigate",
            json={"action": "block_ip", "dry_run": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "block_ip"

    def test_trigger_mitigation_not_found(self, client, mock_orchestrator):
        mock_orchestrator.trigger_mitigation = AsyncMock(return_value=None)
        resp = client.post(
            "/threats/nonexistent/mitigate",
            json={"action": "block_ip", "dry_run": True},
        )
        assert resp.status_code == 404

    def test_trigger_mitigation_invalid_body(self, client):
        resp = client.post(
            "/threats/alert-001/mitigate",
            json={"dry_run": True},  # missing required 'action'
        )
        assert resp.status_code == 422


# ── Graph ─────────────────────────────────────────────────────────

class TestGraph:
    def test_attack_path(self, client):
        resp = client.get("/graph/attack-path/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert "host_ip" in data
        assert "paths" in data

    def test_blast_radius(self, client):
        resp = client.get("/graph/blast-radius/10.0.0.1")
        assert resp.status_code == 200
        data = resp.json()
        assert "host_ip" in data
        assert "reachable_hosts" in data

    def test_compromised_hosts(self, client):
        resp = client.get("/graph/compromised-hosts")
        assert resp.status_code == 200
        assert "hosts" in resp.json()

    def test_technique_frequency(self, client):
        resp = client.get("/graph/technique-frequency")
        assert resp.status_code == 200
        assert "techniques" in resp.json()


# ── Simulation ────────────────────────────────────────────────────

class TestSimulation:
    def test_list_scenarios(self, client):
        resp = client.get("/simulation/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert "scenarios" in data
        assert len(data["scenarios"]) > 0

    def test_get_active_simulations(self, client):
        resp = client.get("/simulation/active")
        assert resp.status_code == 200
        assert "simulations" in resp.json()

    def test_start_simulation(self, client):
        resp = client.post(
            "/simulation/start",
            json={"scenario": "brute_force_ssh", "intensity": 0.5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"
        assert data["scenario"] == "brute_force_ssh"

    def test_start_simulation_invalid_intensity(self, client):
        resp = client.post(
            "/simulation/start",
            json={"scenario": "brute_force_ssh", "intensity": 2.0},  # > 1.0
        )
        assert resp.status_code == 422

    def test_stop_simulation(self, client):
        resp = client.post("/simulation/stop/sim-001")
        assert resp.status_code == 200

    def test_stop_simulation_not_found(self, client, mock_simulator):
        mock_simulator.stop_simulation.return_value = False
        resp = client.post("/simulation/stop/nonexistent")
        assert resp.status_code == 404
