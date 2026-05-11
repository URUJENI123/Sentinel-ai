"""
tests/test_graph.py
────────────────────
Tests for the Neo4j attack graph layer.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from graph.attack_graph import AttackGraph


class TestAttackGraph:
    def _make_graph(self, mock_driver=None) -> AttackGraph:
        graph = AttackGraph.__new__(AttackGraph)
        graph._settings = MagicMock()
        graph._settings.neo4j.uri = "bolt://localhost:7687"
        graph._settings.neo4j.user = "neo4j"
        graph._settings.neo4j.password = "test"
        graph._settings.neo4j.max_connection_pool_size = 10
        graph._settings.neo4j.connection_timeout = 5
        graph._driver = mock_driver
        return graph

    def _make_mock_driver(self):
        driver = MagicMock()
        session = AsyncMock()
        session.run = AsyncMock()
        # Make session work as async context manager
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        driver.session = MagicMock(return_value=session)
        driver.verify_connectivity = AsyncMock()
        driver.close = AsyncMock()
        return driver, session

    @pytest.mark.asyncio
    async def test_upsert_host_calls_session(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.upsert_host("10.0.0.1", hostname="server01", compromised=True)
        session.run.assert_called_once()
        call_args = session.run.call_args[0]
        assert "MERGE (h:Host" in call_args[0]

    @pytest.mark.asyncio
    async def test_upsert_host_no_driver_is_noop(self):
        graph = self._make_graph(None)
        # Should not raise
        await graph.upsert_host("10.0.0.1")

    @pytest.mark.asyncio
    async def test_upsert_user_calls_session(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.upsert_user("alice", host_ip="10.0.0.1")
        assert session.run.call_count >= 1

    @pytest.mark.asyncio
    async def test_add_alert_node(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        alert = {
            "alert_id": "test-alert-001",
            "severity": "HIGH",
            "composite_score": 0.85,
            "anomaly_class": "BRUTE_FORCE",
            "timestamp": "2024-01-01T00:00:00Z",
            "description": "Test alert",
            "source_ip": "192.168.1.100",
            "affected_hosts": ["server01"],
        }
        await graph.add_alert_node(alert)
        assert session.run.call_count >= 1

    @pytest.mark.asyncio
    async def test_add_lateral_movement(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.add_lateral_movement(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            technique_id="T1021",
            confidence=0.9,
        )
        session.run.assert_called_once()
        call_args = session.run.call_args[0]
        assert "LATERAL_MOVE" in call_args[0]

    @pytest.mark.asyncio
    async def test_link_alert_to_technique(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.link_alert_to_technique("alert-001", "T1110", 0.9)
        session.run.assert_called_once()
        call_args = session.run.call_args[0]
        assert "MAPS_TO" in call_args[0]

    @pytest.mark.asyncio
    async def test_get_attack_path_no_driver_returns_empty(self):
        graph = self._make_graph(None)
        result = await graph.get_attack_path("10.0.0.1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_blast_radius_no_driver_returns_default(self):
        graph = self._make_graph(None)
        result = await graph.get_blast_radius("10.0.0.1")
        assert result["host_ip"] == "10.0.0.1"
        assert result["reachable_hosts"] == 0

    @pytest.mark.asyncio
    async def test_get_active_threats_no_driver_returns_empty(self):
        graph = self._make_graph(None)
        result = await graph.get_active_threats()
        assert result == []

    @pytest.mark.asyncio
    async def test_mark_host_contained(self):
        driver, session = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.mark_host_contained("10.0.0.1")
        session.run.assert_called_once()
        call_args = session.run.call_args[0]
        assert "contained" in call_args[0]

    @pytest.mark.asyncio
    async def test_close_calls_driver(self):
        driver, _ = self._make_mock_driver()
        graph = self._make_graph(driver)
        await graph.close()
        driver.close.assert_called_once()
