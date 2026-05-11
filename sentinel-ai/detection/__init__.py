"""Detection layer — heatmap generation, ViT inference, anomaly scoring."""

from detection.log_heatmap import LogHeatmapGenerator
from detection.vision_transformer import LogVisionTransformer
from detection.anomaly_detector import AnomalyDetector, AlertSeverity

__all__ = [
    "LogHeatmapGenerator",
    "LogVisionTransformer",
    "AnomalyDetector",
    "AlertSeverity",
]
