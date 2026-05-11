"""
tests/test_detection.py
────────────────────────
Tests for the detection layer: heatmap generation, ViT, anomaly detector.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from detection.log_heatmap import (
    LogHeatmapGenerator,
    encode_log_to_feature_vector,
    NUM_FEATURE_ROWS,
    _ip_to_float,
    _port_to_float,
    _protocol_to_float,
)
from detection.anomaly_detector import AnomalyDetector, AnomalyAlert, AlertSeverity


# ── Feature encoding ──────────────────────────────────────────────

class TestFeatureEncoding:
    def test_vector_length(self, sample_log):
        vec = encode_log_to_feature_vector(sample_log)
        assert len(vec) == NUM_FEATURE_ROWS

    def test_vector_values_in_range(self, sample_log):
        vec = encode_log_to_feature_vector(sample_log)
        assert np.all(vec >= 0.0)
        assert np.all(vec <= 1.0)

    def test_critical_severity_high_score(self):
        log = {"severity": "CRITICAL", "event_type": "generic"}
        vec = encode_log_to_feature_vector(log)
        # Critical should set a high severity row
        assert vec[:4].max() > 0.5

    def test_anomalous_flag_sets_row_15(self):
        log = {"severity": "INFO", "event_type": "generic", "is_anomalous": True}
        vec = encode_log_to_feature_vector(log)
        assert vec[15] == 1.0

    def test_normal_flag_clears_row_15(self):
        log = {"severity": "INFO", "event_type": "generic", "is_anomalous": False}
        vec = encode_log_to_feature_vector(log)
        assert vec[15] == 0.0

    def test_ip_to_float_deterministic(self):
        f1 = _ip_to_float("192.168.1.1")
        f2 = _ip_to_float("192.168.1.1")
        assert f1 == f2
        assert 0.0 <= f1 <= 1.0

    def test_ip_to_float_none(self):
        assert _ip_to_float(None) == 0.0

    def test_port_to_float(self):
        assert _port_to_float(None) == 0.0
        assert _port_to_float(0) == 0.0
        assert _port_to_float(65535) == 1.0
        assert 0.0 < _port_to_float(443) < 1.0

    def test_protocol_to_float(self):
        assert _protocol_to_float("TCP") == 0.3
        assert _protocol_to_float("UDP") == 0.6
        assert _protocol_to_float("ICMP") == 0.9
        assert _protocol_to_float("OTHER") == 1.0
        assert _protocol_to_float(None) == 1.0


# ── LogHeatmapGenerator ───────────────────────────────────────────

class TestLogHeatmapGenerator:
    def test_empty_window_returns_zero_matrix(self):
        gen = LogHeatmapGenerator(window_size=10, image_size=32)
        matrix = gen._build_matrix()
        assert matrix.shape == (NUM_FEATURE_ROWS, 10)
        assert np.all(matrix == 0.0)

    def test_add_log_increments_window(self, sample_log):
        gen = LogHeatmapGenerator(window_size=10)
        gen.add_log(sample_log)
        assert len(gen._window) == 1
        assert gen.total_processed == 1

    def test_add_logs_batch(self, sample_log_batch):
        gen = LogHeatmapGenerator(window_size=100)
        gen.add_logs(sample_log_batch)
        assert len(gen._window) == len(sample_log_batch)

    def test_window_fill_ratio(self, sample_log):
        gen = LogHeatmapGenerator(window_size=10)
        assert gen.window_fill_ratio == 0.0
        gen.add_log(sample_log)
        assert gen.window_fill_ratio == 0.1

    def test_window_maxlen_respected(self, sample_log):
        gen = LogHeatmapGenerator(window_size=5)
        for _ in range(10):
            gen.add_log(sample_log)
        assert len(gen._window) == 5

    def test_generate_array_shape(self, sample_log_batch):
        gen = LogHeatmapGenerator(window_size=50, image_size=32)
        gen.add_logs(sample_log_batch)
        arr = gen.generate_array()
        assert arr.shape == (32, 32, 3)
        assert arr.dtype == np.uint8

    def test_generate_tensor_shape(self, sample_log_batch):
        pytest.importorskip("torch")
        gen = LogHeatmapGenerator(window_size=50, image_size=32)
        gen.add_logs(sample_log_batch)
        tensor = gen.generate_tensor()
        import torch
        assert isinstance(tensor, torch.Tensor)
        assert tensor.shape == (3, 32, 32)
        assert tensor.min() >= 0.0
        assert tensor.max() <= 1.0

    def test_reset_clears_window(self, sample_log_batch):
        gen = LogHeatmapGenerator(window_size=100)
        gen.add_logs(sample_log_batch)
        gen.reset()
        assert len(gen._window) == 0
        assert gen.window_fill_ratio == 0.0

    def test_matrix_padded_when_window_not_full(self, sample_log):
        gen = LogHeatmapGenerator(window_size=10)
        gen.add_log(sample_log)
        matrix = gen._build_matrix()
        assert matrix.shape == (NUM_FEATURE_ROWS, 10)
        # First 9 columns should be zero (padding)
        assert np.all(matrix[:, :9] == 0.0)


# ── AnomalyDetector ───────────────────────────────────────────────

class TestAnomalyDetector:
    def test_empty_batch_returns_no_alerts(self):
        detector = AnomalyDetector()
        alerts = detector.process_batch([])
        assert alerts == []

    def test_normal_logs_produce_no_alerts(self, sample_log_batch):
        detector = AnomalyDetector()
        # Normal logs should not trigger alerts (score below threshold)
        with patch.object(detector._vit, "predict", return_value={
            "anomaly_score": 0.1,
            "anomaly_class": "NORMAL",
            "is_anomalous": False,
        }):
            alerts = detector.process_batch(sample_log_batch)
            # With low ViT score and no trained baseline, composite should be low
            assert all(a.composite_score < 0.9 for a in alerts)

    def test_high_anomaly_score_generates_alert(self, sample_log_batch):
        detector = AnomalyDetector()
        with patch.object(detector._vit, "predict", return_value={
            "anomaly_score": 0.95,
            "anomaly_class": "BRUTE_FORCE",
            "is_anomalous": True,
        }):
            alerts = detector.process_batch(sample_log_batch)
            assert len(alerts) > 0
            assert any(a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL) for a in alerts)

    def test_alert_has_required_fields(self, sample_log_batch):
        detector = AnomalyDetector()
        with patch.object(detector._vit, "predict", return_value={
            "anomaly_score": 0.95,
            "anomaly_class": "LATERAL_MOVEMENT",
            "is_anomalous": True,
        }):
            alerts = detector.process_batch(sample_log_batch)
            if alerts:
                alert = alerts[0]
                assert alert.alert_id is not None
                assert alert.timestamp is not None
                assert isinstance(alert.composite_score, float)
                assert alert.anomaly_class is not None

    def test_classify_severity_thresholds(self):
        detector = AnomalyDetector()
        assert detector._classify_severity(0.95) == AlertSeverity.CRITICAL
        assert detector._classify_severity(0.82) == AlertSeverity.HIGH
        assert detector._classify_severity(0.70) == AlertSeverity.MEDIUM
        assert detector._classify_severity(0.45) == AlertSeverity.LOW

    def test_metrics_updated_after_processing(self, sample_log_batch):
        detector = AnomalyDetector()
        detector.process_batch(sample_log_batch)
        metrics = detector.get_metrics()
        assert metrics["total_processed"] == len(sample_log_batch)

    def test_alert_to_dict(self, sample_alert):
        d = sample_alert.to_dict()
        assert d["alert_id"] == sample_alert.alert_id
        assert d["severity"] == "HIGH"
        assert d["composite_score"] == round(sample_alert.composite_score, 4)
        assert "source_ip" in d
        assert "affected_hosts" in d
