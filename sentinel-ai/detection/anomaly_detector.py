"""
detection/anomaly_detector.py
──────────────────────────────
Combines ViT anomaly scores with statistical methods (Isolation Forest,
z-score) to produce a composite anomaly score and emit structured alerts.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config.settings import get_settings
from detection.log_heatmap import LogHeatmapGenerator, encode_log_to_feature_vector
from detection.vision_transformer import LogVisionTransformer


# ── Alert severity ────────────────────────────────────────────────


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Alert model ───────────────────────────────────────────────────


@dataclass
class AnomalyAlert:
    """Structured anomaly alert emitted by the detector."""

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    severity: AlertSeverity = AlertSeverity.LOW
    composite_score: float = 0.0
    vit_score: float = 0.0
    isolation_score: float = 0.0
    zscore: float = 0.0
    anomaly_class: str = "NORMAL"
    source_ip: Optional[str] = None
    affected_hosts: List[str] = field(default_factory=list)
    event_count: int = 0
    raw_logs: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "composite_score": round(self.composite_score, 4),
            "vit_score": round(self.vit_score, 4),
            "isolation_score": round(self.isolation_score, 4),
            "zscore": round(self.zscore, 4),
            "anomaly_class": self.anomaly_class,
            "source_ip": self.source_ip,
            "affected_hosts": self.affected_hosts,
            "event_count": self.event_count,
            "description": self.description,
            "confidence": round(self.confidence, 4),
        }


# ── Baseline profile ──────────────────────────────────────────────


@dataclass
class BaselineProfile:
    """Per-entity (IP/user) statistical baseline."""

    entity_id: str
    feature_history: Deque[np.ndarray] = field(
        default_factory=lambda: deque(maxlen=1000)
    )
    score_history: Deque[float] = field(default_factory=lambda: deque(maxlen=500))
    isolation_forest: Optional[IsolationForest] = None
    scaler: Optional[StandardScaler] = None
    last_trained: float = 0.0
    sample_count: int = 0

    def add_sample(self, features: np.ndarray, score: float) -> None:
        self.feature_history.append(features)
        self.score_history.append(score)
        self.sample_count += 1

    def train(self, contamination: float = 0.05) -> None:
        """Fit Isolation Forest on accumulated feature history."""
        if len(self.feature_history) < 20:
            return
        X = np.stack(list(self.feature_history))
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
        )
        self.isolation_forest.fit(X_scaled)
        self.last_trained = time.monotonic()

    def predict_isolation(self, features: np.ndarray) -> float:
        """
        Return an anomaly score in [0, 1] from Isolation Forest.
        1.0 = most anomalous.
        """
        if self.isolation_forest is None or self.scaler is None:
            return 0.5  # neutral when not trained

        X = features.reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        # decision_function returns negative values for anomalies
        raw = self.isolation_forest.decision_function(X_scaled)[0]
        # Normalise: typical range is [-0.5, 0.5]; flip and scale to [0, 1]
        score = 1.0 - (raw + 0.5)
        return float(np.clip(score, 0.0, 1.0))

    def compute_zscore(self, score: float) -> float:
        """Compute z-score of a new score against the history."""
        if len(self.score_history) < 10:
            return 0.0
        arr = np.array(list(self.score_history))
        mean, std = arr.mean(), arr.std()
        if std < 1e-9:
            return 0.0
        return float(abs((score - mean) / std))


# ── AnomalyDetector ───────────────────────────────────────────────


class AnomalyDetector:
    """
    Composite anomaly detector combining:
        1. Vision Transformer (ViT) on log heatmaps
        2. Per-entity Isolation Forest
        3. Z-score against rolling baseline

    Emits AnomalyAlert objects with severity levels.

    Usage::

        detector = AnomalyDetector()
        alerts = detector.process_batch(log_batch)
        for alert in alerts:
            print(alert.to_dict())
    """

    # Weights for composite score
    VIT_WEIGHT = 0.50
    ISOLATION_WEIGHT = 0.30
    ZSCORE_WEIGHT = 0.20

    def __init__(self) -> None:
        self._settings = get_settings()
        self._det_cfg = self._settings.detection
        self._vit = LogVisionTransformer()
        self._heatmap_gen = LogHeatmapGenerator(
            window_size=self._settings.vit.image_size,
            image_size=self._settings.vit.image_size,
        )
        self._baselines: Dict[str, BaselineProfile] = defaultdict(
            lambda: BaselineProfile(entity_id="unknown")
        )
        self._global_baseline = BaselineProfile(entity_id="global")
        self._retrain_interval = 300  # seconds between retraining
        self._total_processed: int = 0
        self._total_alerts: int = 0

        # Load ViT weights if available
        self._vit.load_weights()

    # ── Core processing ───────────────────────────────────────────

    def process_batch(self, logs: List[Dict[str, Any]]) -> List[AnomalyAlert]:
        """
        Process a batch of normalised log events and return any alerts.

        Steps:
            1. Update heatmap window
            2. Run ViT inference
            3. Per-entity Isolation Forest scoring
            4. Z-score computation
            5. Composite scoring and alert generation
        """
        if not logs:
            return []

        self._total_processed += len(logs)

        # Update heatmap
        self._heatmap_gen.add_logs(logs)

        # ViT inference (only when window is reasonably full)
        vit_result = {"anomaly_score": 0.0, "anomaly_class": "NORMAL", "is_anomalous": False}
        if self._heatmap_gen.window_fill_ratio >= 0.1:
            try:
                tensor = self._heatmap_gen.generate_tensor()
                vit_result = self._vit.predict(tensor)
            except Exception as exc:
                logger.warning("ViT inference failed: {}", exc)

        # Group logs by source entity
        entity_logs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for log in logs:
            entity = log.get("source_ip") or log.get("host") or "unknown"
            entity_logs[entity].append(log)

        alerts: List[AnomalyAlert] = []

        for entity, entity_batch in entity_logs.items():
            alert = self._score_entity(entity, entity_batch, vit_result)
            if alert:
                alerts.append(alert)
                self._total_alerts += 1

        # Periodically retrain baselines
        self._maybe_retrain_baselines()

        return alerts

    def _score_entity(
        self,
        entity: str,
        logs: List[Dict[str, Any]],
        vit_result: Dict[str, Any],
    ) -> Optional[AnomalyAlert]:
        """Score a single entity's log batch and return an alert if anomalous."""

        # Aggregate feature vector for this entity
        features = np.mean(
            [encode_log_to_feature_vector(log) for log in logs], axis=0
        )

        # Ensure baseline profile exists
        if entity not in self._baselines:
            self._baselines[entity] = BaselineProfile(entity_id=entity)

        profile = self._baselines[entity]

        # Isolation Forest score
        iso_score = profile.predict_isolation(features)

        # Z-score against entity's own history
        vit_score = vit_result.get("anomaly_score", 0.0)
        profile.add_sample(features, vit_score)
        z = profile.compute_zscore(vit_score)
        # Normalise z-score to [0, 1] (z=3 → 1.0)
        z_normalised = float(np.clip(z / 3.0, 0.0, 1.0))

        # Composite score
        composite = (
            self.VIT_WEIGHT * vit_score
            + self.ISOLATION_WEIGHT * iso_score
            + self.ZSCORE_WEIGHT * z_normalised
        )

        # Determine severity
        severity = self._classify_severity(composite)

        # Only emit alert above LOW threshold
        if composite < self._det_cfg.low_threshold:
            return None

        # Collect affected hosts
        hosts = list({log.get("host") for log in logs if log.get("host")})

        # Build description
        anomaly_class = vit_result.get("anomaly_class", "UNKNOWN")
        description = (
            f"Anomalous activity detected from {entity}. "
            f"ViT class: {anomaly_class}, composite score: {composite:.3f}. "
            f"Analysed {len(logs)} events."
        )

        alert = AnomalyAlert(
            severity=severity,
            composite_score=composite,
            vit_score=vit_score,
            isolation_score=iso_score,
            zscore=z,
            anomaly_class=anomaly_class,
            source_ip=entity if "." in entity else None,
            affected_hosts=hosts,
            event_count=len(logs),
            raw_logs=logs[:5],  # include first 5 for context
            description=description,
            confidence=composite,
        )

        logger.info(
            "Alert generated: severity={} score={:.3f} entity={} class={}",
            severity.value, composite, entity, anomaly_class,
        )
        return alert

    def _classify_severity(self, score: float) -> AlertSeverity:
        """Map composite score to severity level."""
        cfg = self._det_cfg
        if score >= cfg.critical_threshold:
            return AlertSeverity.CRITICAL
        if score >= cfg.high_threshold:
            return AlertSeverity.HIGH
        if score >= cfg.medium_threshold:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _maybe_retrain_baselines(self) -> None:
        """Retrain Isolation Forest models for entities with enough data."""
        now = time.monotonic()
        for entity, profile in self._baselines.items():
            if (
                profile.sample_count >= self._settings.detection.min_baseline_samples
                and now - profile.last_trained > self._retrain_interval
            ):
                try:
                    profile.train(self._det_cfg.isolation_forest_contamination)
                    logger.debug("Retrained baseline for entity: {}", entity)
                except Exception as exc:
                    logger.warning("Baseline retrain failed for {}: {}", entity, exc)

    # ── Metrics ───────────────────────────────────────────────────

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_processed": self._total_processed,
            "total_alerts": self._total_alerts,
            "tracked_entities": len(self._baselines),
            "heatmap_fill_ratio": round(self._heatmap_gen.window_fill_ratio, 3),
            "vit_device": self._vit.device,
        }
