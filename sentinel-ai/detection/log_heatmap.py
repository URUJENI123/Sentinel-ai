"""
detection/log_heatmap.py
─────────────────────────
Converts sequences of normalised log events into 2D heatmap images
suitable for input to the Vision Transformer.

Encoding:
    X-axis  : time (sliding window, newest on the right)
    Y-axis  : feature channels (severity, event_type, source_ip bucket, etc.)
    Intensity: frequency / severity score in each cell
"""

from __future__ import annotations

import hashlib
import io
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

# PIL and matplotlib are optional at import time so the module can be
# imported even if they are not installed (tests, CI).
try:
    from PIL import Image
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    _IMAGING_AVAILABLE = True
except ImportError:
    _IMAGING_AVAILABLE = False
    logger.warning("PIL/matplotlib not available — heatmap generation disabled")


# ── Feature encoding helpers ──────────────────────────────────────

SEVERITY_SCORES: Dict[str, float] = {
    "DEBUG": 0.05,
    "INFO": 0.1,
    "NOTICE": 0.2,
    "WARNING": 0.4,
    "ERROR": 0.7,
    "CRITICAL": 0.9,
    "ALERT": 1.0,
}

EVENT_TYPE_BUCKETS: Dict[str, int] = {
    "authentication": 0,
    "login": 0,
    "logout": 0,
    "network": 1,
    "connection": 1,
    "packet": 1,
    "process": 2,
    "execution": 2,
    "file": 3,
    "registry": 4,
    "dns": 5,
    "http": 6,
    "generic": 7,
}

NUM_FEATURE_ROWS = 16  # Y-axis height (feature channels)
# Row assignments:
#   0-3   : severity bands (DEBUG/INFO/WARNING/ERROR+)
#   4-7   : event type buckets
#   8-11  : source IP octets (hashed to 0-1)
#   12    : payload size (normalised)
#   13    : port bucket
#   14    : protocol (TCP=0.3, UDP=0.6, ICMP=0.9, OTHER=1.0)
#   15    : composite anomaly score


def _ip_to_float(ip: Optional[str]) -> float:
    """Hash an IP address to a float in [0, 1]."""
    if not ip:
        return 0.0
    digest = hashlib.md5(ip.encode()).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def _event_type_to_row(event_type: str) -> int:
    """Map event type string to a feature row index (4-7)."""
    et_lower = event_type.lower()
    for keyword, bucket in EVENT_TYPE_BUCKETS.items():
        if keyword in et_lower:
            return 4 + bucket
    return 4 + 7  # generic


def _port_to_float(port: Optional[int]) -> float:
    """Normalise a port number to [0, 1]."""
    if port is None:
        return 0.0
    return min(port / 65535.0, 1.0)


def _protocol_to_float(protocol: Optional[str]) -> float:
    mapping = {"TCP": 0.3, "UDP": 0.6, "ICMP": 0.9}
    return mapping.get((protocol or "").upper(), 1.0)


def encode_log_to_feature_vector(log: Dict[str, Any]) -> np.ndarray:
    """
    Convert a single normalised log event to a feature vector of
    length NUM_FEATURE_ROWS.
    """
    vec = np.zeros(NUM_FEATURE_ROWS, dtype=np.float32)

    # Severity rows (0-3)
    severity = log.get("severity", "INFO")
    sev_score = SEVERITY_SCORES.get(severity, 0.1)
    sev_row = min(int(sev_score * 4), 3)
    vec[sev_row] = sev_score

    # Event type rows (4-11)
    event_type = log.get("event_type", "generic")
    et_row = _event_type_to_row(event_type)
    vec[et_row] = 1.0

    # Source IP rows (8-11)
    src_ip = log.get("source_ip") or log.get("src_ip")
    ip_float = _ip_to_float(src_ip)
    ip_row = 8 + int(ip_float * 4)
    vec[min(ip_row, 11)] = ip_float

    # Payload size (12)
    payload = log.get("payload_size", 0) or 0
    vec[12] = min(payload / 65535.0, 1.0)

    # Port (13)
    port = log.get("dst_port") or log.get("src_port")
    vec[13] = _port_to_float(port)

    # Protocol (14)
    protocol = log.get("protocol")
    vec[14] = _protocol_to_float(protocol)

    # Composite anomaly hint (15)
    vec[15] = 1.0 if log.get("is_anomalous") else 0.0

    return vec


# ── LogHeatmapGenerator ───────────────────────────────────────────


class LogHeatmapGenerator:
    """
    Maintains a sliding window of log events and generates 2D heatmap
    images for Vision Transformer input.

    The output image is (image_size x image_size) with 3 channels (RGB),
    where each column represents a time step and each row a feature channel.

    Usage::

        gen = LogHeatmapGenerator(window_size=224)
        gen.add_logs(batch_of_logs)
        image_tensor = gen.generate_tensor()   # torch.Tensor [3, 224, 224]
        pil_image    = gen.generate_pil()      # PIL.Image
    """

    def __init__(
        self,
        window_size: int = 224,
        image_size: int = 224,
        colormap: str = "hot",
    ) -> None:
        """
        Args:
            window_size: Number of log events in the sliding window (= image width).
            image_size:  Output image size in pixels (square).
            colormap:    Matplotlib colormap name for heatmap rendering.
        """
        self._window_size = window_size
        self._image_size = image_size
        self._colormap = colormap
        self._window: Deque[np.ndarray] = deque(maxlen=window_size)
        self._total_processed: int = 0

    # ── Data ingestion ────────────────────────────────────────────

    def add_log(self, log: Dict[str, Any]) -> None:
        """Add a single log event to the sliding window."""
        vec = encode_log_to_feature_vector(log)
        self._window.append(vec)
        self._total_processed += 1

    def add_logs(self, logs: List[Dict[str, Any]]) -> None:
        """Add a batch of log events to the sliding window."""
        for log in logs:
            self.add_log(log)

    # ── Matrix construction ───────────────────────────────────────

    def _build_matrix(self) -> np.ndarray:
        """
        Build the (NUM_FEATURE_ROWS x window_size) heatmap matrix.
        Columns are time steps (oldest left, newest right).
        Rows are feature channels.
        """
        n_cols = len(self._window)
        if n_cols == 0:
            return np.zeros((NUM_FEATURE_ROWS, self._window_size), dtype=np.float32)

        # Stack window into matrix: shape (n_cols, NUM_FEATURE_ROWS)
        matrix = np.stack(list(self._window), axis=0)  # (n_cols, features)
        matrix = matrix.T  # (features, n_cols)

        # Pad with zeros on the left if window not full
        if n_cols < self._window_size:
            pad = np.zeros((NUM_FEATURE_ROWS, self._window_size - n_cols), dtype=np.float32)
            matrix = np.concatenate([pad, matrix], axis=1)

        return matrix.astype(np.float32)

    # ── Image generation ──────────────────────────────────────────

    def generate_array(self) -> np.ndarray:
        """
        Generate a (image_size, image_size, 3) uint8 numpy array.
        """
        matrix = self._build_matrix()

        if not _IMAGING_AVAILABLE:
            # Fallback: return a simple grayscale-to-RGB array
            resized = np.repeat(
                np.expand_dims(
                    np.kron(
                        matrix,
                        np.ones((
                            self._image_size // NUM_FEATURE_ROWS + 1,
                            self._image_size // self._window_size + 1,
                        )),
                    )[: self._image_size, : self._image_size],
                    axis=-1,
                ),
                3,
                axis=-1,
            )
            return (resized * 255).astype(np.uint8)

        # Use matplotlib to apply colormap
        cmap = plt.get_cmap(self._colormap)
        rgba = cmap(matrix)  # (features, window_size, 4)
        rgb = (rgba[:, :, :3] * 255).astype(np.uint8)

        # Resize to target image size using PIL
        pil = Image.fromarray(rgb).resize(
            (self._image_size, self._image_size), Image.LANCZOS
        )
        return np.array(pil)

    def generate_pil(self) -> Optional[Any]:
        """Generate a PIL Image object."""
        if not _IMAGING_AVAILABLE:
            return None
        arr = self.generate_array()
        return Image.fromarray(arr)

    def generate_tensor(self) -> Any:
        """
        Generate a normalised PyTorch tensor of shape (3, image_size, image_size).
        Pixel values are normalised to [0, 1].
        """
        try:
            import torch
            arr = self.generate_array()
            tensor = torch.from_numpy(arr).permute(2, 0, 1).float() / 255.0
            return tensor
        except ImportError:
            logger.warning("PyTorch not available — returning numpy array")
            return self.generate_array()

    def save_image(self, path: str) -> None:
        """Save the current heatmap to a file."""
        pil = self.generate_pil()
        if pil:
            pil.save(path)
            logger.debug("Heatmap saved to {}", path)

    def get_bytes(self, fmt: str = "PNG") -> bytes:
        """Return the heatmap image as bytes."""
        pil = self.generate_pil()
        if not pil:
            return b""
        buf = io.BytesIO()
        pil.save(buf, format=fmt)
        return buf.getvalue()

    # ── State ─────────────────────────────────────────────────────

    @property
    def window_fill_ratio(self) -> float:
        """How full the sliding window is (0.0 to 1.0)."""
        return len(self._window) / self._window_size

    @property
    def total_processed(self) -> int:
        return self._total_processed

    def reset(self) -> None:
        """Clear the sliding window."""
        self._window.clear()
