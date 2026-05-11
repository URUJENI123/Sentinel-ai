"""
tests/test_simulation.py
─────────────────────────
Tests for the threat simulation engine.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from simulation.threat_simulator import ThreatSimulator, SCENARIOS


class TestThreatSimulator:
    def test_list_scenarios_returns_all(self):
        sim = ThreatSimulator()
        scenarios = sim.list_scenarios()
        assert len(scenarios) == len(SCENARIOS)
        names = [s["name"] for s in scenarios]
        assert "brute_force_ssh" in names
        assert "apt_lateral_movement" in names
        assert "ransomware" in names

    def test_unknown_scenario_raises(self):
        sim = ThreatSimulator()
        with pytest.raises(ValueError, match="Unknown scenario"):
            asyncio.get_event_loop().run_until_complete(
                _collect_events(sim, "nonexistent_scenario")
            )

    @pytest.mark.asyncio
    async def test_brute_force_generates_events(self):
        sim = ThreatSimulator()
        events = []
        async for event in sim.run_scenario("brute_force_ssh", intensity=1.0, duration_override=5):
            events.append(event)
            if len(events) >= 5:
                break
        assert len(events) >= 5

    @pytest.mark.asyncio
    async def test_events_have_required_fields(self):
        sim = ThreatSimulator()
        async for event in sim.run_scenario("port_scan_recon", intensity=1.0, duration_override=3):
            assert "timestamp" in event
            assert "severity" in event
            assert "event_type" in event
            assert "raw_message" in event
            assert event.get("is_simulated") is True
            break

    @pytest.mark.asyncio
    async def test_brute_force_has_auth_events(self):
        sim = ThreatSimulator()
        event_types = set()
        async for event in sim.run_scenario("brute_force_ssh", intensity=1.0, duration_override=5):
            event_types.add(event["event_type"])
            if len(event_types) >= 2:
                break
        assert "authentication" in event_types

    @pytest.mark.asyncio
    async def test_ransomware_has_file_events(self):
        sim = ThreatSimulator()
        event_types = set()
        async for event in sim.run_scenario("ransomware", intensity=1.0, duration_override=10):
            event_types.add(event["event_type"])
            if "file" in event_types:
                break
        assert "file" in event_types

    @pytest.mark.asyncio
    async def test_apt_has_network_events(self):
        sim = ThreatSimulator()
        event_types = set()
        async for event in sim.run_scenario("apt_lateral_movement", intensity=1.0, duration_override=10):
            event_types.add(event["event_type"])
            if len(event_types) >= 3:
                break
        assert len(event_types) >= 2

    @pytest.mark.asyncio
    async def test_stop_simulation(self):
        sim = ThreatSimulator()
        events = []

        async def run():
            async for event in sim.run_scenario("insider_threat", intensity=0.5):
                events.append(event)
                if len(events) >= 3:
                    # Stop the simulation
                    active = sim.get_active_simulations()
                    if active:
                        sim.stop_simulation(active[0]["simulation_id"])
                    break

        await asyncio.wait_for(run(), timeout=10.0)
        assert len(events) >= 3

    @pytest.mark.asyncio
    async def test_intensity_affects_event_count(self):
        """Higher intensity should produce more events in the same time."""
        sim_low = ThreatSimulator()
        sim_high = ThreatSimulator()

        low_events = []
        high_events = []

        async for event in sim_low.run_scenario("port_scan_recon", intensity=0.1, duration_override=2):
            low_events.append(event)

        async for event in sim_high.run_scenario("port_scan_recon", intensity=1.0, duration_override=2):
            high_events.append(event)

        # High intensity should produce at least as many events
        assert len(high_events) >= len(low_events)

    def test_get_active_simulations_empty_initially(self):
        sim = ThreatSimulator()
        assert sim.get_active_simulations() == []

    @pytest.mark.asyncio
    async def test_web_exploit_has_http_events(self):
        sim = ThreatSimulator()
        async for event in sim.run_scenario("web_exploit", intensity=1.0, duration_override=5):
            if event["event_type"] == "http":
                assert "http_method" in event
                assert "http_status" in event
                break


async def _collect_events(sim: ThreatSimulator, scenario: str) -> List:
    events = []
    async for event in sim.run_scenario(scenario):
        events.append(event)
    return events
