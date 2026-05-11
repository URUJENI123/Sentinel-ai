"""
tests/test_ingestion.py
────────────────────────
Tests for the log and packet ingestion layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ingestion.log_ingester import LogIngester, normalise_log, _normalise_severity
from ingestion.packet_ingester import PacketIngester, PacketFeatures, PortScanTracker, TransferTracker


# ── normalise_log ─────────────────────────────────────────────────

class TestNormaliseLog:
    def test_basic_normalisation(self):
        raw = {
            "_source": {
                "@timestamp": "2024-01-01T00:00:00Z",
                "source.ip": "10.0.0.1",
                "destination.ip": "10.0.0.2",
                "event.action": "login",
                "message": "User logged in",
                "log.level": "info",
                "host.name": "server01",
                "user.name": "alice",
            }
        }
        result = normalise_log(raw, "sentinel-auth")
        assert result["source_ip"] == "10.0.0.1"
        assert result["dest_ip"] == "10.0.0.2"
        assert result["event_type"] == "login"
        assert result["severity"] == "INFO"
        assert result["host"] == "server01"
        assert result["user"] == "alice"
        assert result["index"] == "sentinel-auth"

    def test_missing_fields_use_defaults(self):
        raw = {"_source": {"message": "bare log"}}
        result = normalise_log(raw, "test-index")
        assert result["severity"] == "INFO"
        assert result["event_type"] == "generic"
        assert result["source_ip"] is None
        assert result["dest_ip"] is None

    def test_raw_message_capped_at_4096(self):
        raw = {"_source": {"message": "x" * 5000}}
        result = normalise_log(raw, "test")
        assert len(result["raw_message"]) == 4096

    def test_extra_fields_captured(self):
        raw = {"_source": {"message": "test", "custom_field": "custom_value"}}
        result = normalise_log(raw, "test")
        assert result["extra"].get("custom_field") == "custom_value"

    def test_flat_doc_without_source_wrapper(self):
        raw = {"message": "flat doc", "log.level": "error"}
        result = normalise_log(raw, "test")
        assert result["severity"] == "ERROR"


class TestNormaliseSeverity:
    def test_string_severity(self):
        assert _normalise_severity("warning") == "WARNING"
        assert _normalise_severity("ERROR") == "ERROR"

    def test_integer_severity(self):
        assert _normalise_severity(0) == "DEBUG"
        assert _normalise_severity(4) == "ERROR"

    def test_unknown_defaults_to_info(self):
        assert _normalise_severity(None) == "INFO"


# ── LogIngester ───────────────────────────────────────────────────

class TestLogIngester:
    @pytest.mark.asyncio
    async def test_connect_and_close(self, mock_es_client):
        ingester = LogIngester()
        with patch("ingestion.log_ingester.AsyncElasticsearch", return_value=mock_es_client):
            await ingester.connect()
            assert ingester._client is not None
            await ingester.close()

    @pytest.mark.asyncio
    async def test_fetch_batch_returns_normalised_logs(self, mock_es_client):
        mock_es_client.search = AsyncMock(return_value={
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "@timestamp": "2024-01-01T00:00:00Z",
                            "message": "test log",
                            "log.level": "info",
                        }
                    }
                ]
            }
        })
        ingester = LogIngester()
        ingester._client = mock_es_client
        batch = await ingester.fetch_batch()
        assert len(batch) == 4  # 4 indices, 1 hit each
        assert batch[0]["raw_message"] == "test log"

    @pytest.mark.asyncio
    async def test_fetch_batch_handles_index_error(self, mock_es_client):
        mock_es_client.search = AsyncMock(side_effect=Exception("ES error"))
        ingester = LogIngester()
        ingester._client = mock_es_client
        batch = await ingester.fetch_batch()
        assert batch == []

    def test_metrics(self):
        ingester = LogIngester()
        ingester._total_ingested = 42
        metrics = ingester.get_metrics()
        assert metrics["total_ingested"] == 42


# ── PortScanTracker ───────────────────────────────────────────────

class TestPortScanTracker:
    def test_no_scan_below_threshold(self):
        tracker = PortScanTracker(threshold=20)
        for port in range(10):
            result = tracker.record("10.0.0.1", port)
        assert result is False

    def test_scan_detected_at_threshold(self):
        tracker = PortScanTracker(threshold=5, window_seconds=60)
        results = [tracker.record("10.0.0.1", port) for port in range(5)]
        assert results[-1] is True

    def test_different_ips_tracked_independently(self):
        tracker = PortScanTracker(threshold=5)
        for port in range(4):
            tracker.record("10.0.0.1", port)
        # Different IP should not trigger
        result = tracker.record("10.0.0.2", 80)
        assert result is False


# ── TransferTracker ───────────────────────────────────────────────

class TestTransferTracker:
    def test_no_alert_below_threshold(self):
        tracker = TransferTracker(threshold_bytes=50_000_000)
        result = tracker.record("10.0.0.1", "10.0.0.2", 1000)
        assert result is False

    def test_alert_at_threshold(self):
        tracker = TransferTracker(threshold_bytes=1000)
        tracker.record("10.0.0.1", "10.0.0.2", 500)
        result = tracker.record("10.0.0.1", "10.0.0.2", 600)
        assert result is True


# ── PacketIngester ────────────────────────────────────────────────

class TestPacketIngester:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        ingester = PacketIngester()
        await ingester.start()
        assert ingester._running is True
        await ingester.stop()
        assert ingester._running is False

    @pytest.mark.asyncio
    async def test_simulation_mode_generates_packets(self):
        ingester = PacketIngester()
        ingester._running = True
        packets = []

        # Run simulation briefly
        import asyncio
        async def collect():
            async for pkt in ingester.stream_packets():
                packets.append(pkt)
                if len(packets) >= 3:
                    ingester._running = False
                    break

        ingester._running = True
        sim_task = asyncio.create_task(ingester._simulate_packets())
        await asyncio.sleep(0.5)
        ingester._running = False
        sim_task.cancel()

    def test_suspicious_port_detection(self):
        ingester = PacketIngester()
        features = PacketFeatures(
            timestamp="2024-01-01T00:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
            src_port=12345,
            dst_port=4444,  # known RAT port
            payload_size=100,
            flags=["SYN"],
            ttl=64,
        )
        result = ingester._detect_anomalies(features)
        assert result.is_anomalous is True
        assert result.anomaly_type == "SUSPICIOUS_PORT"

    def test_metrics(self):
        ingester = PacketIngester()
        ingester._total_captured = 100
        ingester._total_anomalies = 5
        metrics = ingester.get_metrics()
        assert metrics["total_captured"] == 100
        assert metrics["anomaly_rate"] == 0.05
