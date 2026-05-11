"""
detection/vision_transformer.py
─────────────────────────────────
Vision Transformer (ViT) implementation for log anomaly detection.
Takes 224×224 RGB heatmap images and outputs an anomaly score (0–1)
plus an anomaly class label.

Architecture follows "An Image is Worth 16x16 Words" (Dosovitskiy et al.)
with a classification head adapted for anomaly scoring.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False
    logger.warning("PyTorch not available — ViT will run in mock mode")

from config.settings import get_settings

# ── Anomaly class labels ──────────────────────────────────────────

ANOMALY_CLASSES: List[str] = [
    "NORMAL",
    "BRUTE_FORCE",
    "LATERAL_MOVEMENT",
    "DATA_EXFILTRATION",
    "MALWARE_EXECUTION",
]


# ── ViT building blocks ───────────────────────────────────────────

if _TORCH_AVAILABLE:

    class PatchEmbedding(nn.Module):
        """
        Split image into non-overlapping patches and project to embedding dim.

        Input:  (B, C, H, W)
        Output: (B, num_patches, embed_dim)
        """

        def __init__(
            self,
            image_size: int = 224,
            patch_size: int = 16,
            in_channels: int = 3,
            embed_dim: int = 768,
        ) -> None:
            super().__init__()
            assert image_size % patch_size == 0, "Image size must be divisible by patch size"
            self.num_patches = (image_size // patch_size) ** 2
            self.patch_size = patch_size
            # Conv2d with kernel=patch_size, stride=patch_size acts as patch extraction + projection
            self.projection = nn.Conv2d(
                in_channels, embed_dim, kernel_size=patch_size, stride=patch_size
            )

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            # x: (B, C, H, W) → (B, embed_dim, H/P, W/P) → (B, num_patches, embed_dim)
            x = self.projection(x)
            x = x.flatten(2).transpose(1, 2)
            return x

    class MultiHeadSelfAttention(nn.Module):
        """Standard multi-head self-attention with dropout."""

        def __init__(
            self,
            embed_dim: int = 768,
            num_heads: int = 12,
            dropout: float = 0.0,
        ) -> None:
            super().__init__()
            assert embed_dim % num_heads == 0
            self.num_heads = num_heads
            self.head_dim = embed_dim // num_heads
            self.scale = self.head_dim ** -0.5

            self.qkv = nn.Linear(embed_dim, embed_dim * 3, bias=True)
            self.proj = nn.Linear(embed_dim, embed_dim)
            self.attn_drop = nn.Dropout(dropout)
            self.proj_drop = nn.Dropout(dropout)

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            B, N, C = x.shape
            qkv = self.qkv(x).reshape(B, N, 3, self.num_heads, self.head_dim)
            qkv = qkv.permute(2, 0, 3, 1, 4)
            q, k, v = qkv.unbind(0)

            attn = (q @ k.transpose(-2, -1)) * self.scale
            attn = F.softmax(attn, dim=-1)
            attn = self.attn_drop(attn)

            x = (attn @ v).transpose(1, 2).reshape(B, N, C)
            x = self.proj(x)
            x = self.proj_drop(x)
            return x

    class MLP(nn.Module):
        """Feed-forward MLP block used inside each transformer layer."""

        def __init__(
            self,
            in_features: int,
            hidden_features: int,
            dropout: float = 0.0,
        ) -> None:
            super().__init__()
            self.fc1 = nn.Linear(in_features, hidden_features)
            self.act = nn.GELU()
            self.fc2 = nn.Linear(hidden_features, in_features)
            self.drop = nn.Dropout(dropout)

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            x = self.fc1(x)
            x = self.act(x)
            x = self.drop(x)
            x = self.fc2(x)
            x = self.drop(x)
            return x

    class TransformerBlock(nn.Module):
        """Single Vision Transformer encoder block."""

        def __init__(
            self,
            embed_dim: int = 768,
            num_heads: int = 12,
            mlp_ratio: float = 4.0,
            dropout: float = 0.0,
        ) -> None:
            super().__init__()
            self.norm1 = nn.LayerNorm(embed_dim)
            self.attn = MultiHeadSelfAttention(embed_dim, num_heads, dropout)
            self.norm2 = nn.LayerNorm(embed_dim)
            self.mlp = MLP(embed_dim, int(embed_dim * mlp_ratio), dropout)

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            x = x + self.attn(self.norm1(x))
            x = x + self.mlp(self.norm2(x))
            return x

    class VisionTransformer(nn.Module):
        """
        Full Vision Transformer for anomaly classification.

        Input:  (B, 3, image_size, image_size)
        Output: (B, num_classes)  — raw logits
        """

        def __init__(
            self,
            image_size: int = 224,
            patch_size: int = 16,
            in_channels: int = 3,
            num_classes: int = 5,
            embed_dim: int = 768,
            num_heads: int = 12,
            num_layers: int = 12,
            mlp_ratio: float = 4.0,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            self.patch_embed = PatchEmbedding(image_size, patch_size, in_channels, embed_dim)
            num_patches = self.patch_embed.num_patches

            # Learnable [CLS] token and positional embeddings
            self.cls_token = nn.Parameter(torch.zeros(1, 1, embed_dim))
            self.pos_embed = nn.Parameter(torch.zeros(1, num_patches + 1, embed_dim))
            self.pos_drop = nn.Dropout(dropout)

            # Transformer encoder
            self.blocks = nn.ModuleList([
                TransformerBlock(embed_dim, num_heads, mlp_ratio, dropout)
                for _ in range(num_layers)
            ])
            self.norm = nn.LayerNorm(embed_dim)

            # Classification head
            self.head = nn.Sequential(
                nn.Linear(embed_dim, embed_dim // 2),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(embed_dim // 2, num_classes),
            )

            # Anomaly score head (single sigmoid output)
            self.anomaly_head = nn.Sequential(
                nn.Linear(embed_dim, 256),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(256, 1),
                nn.Sigmoid(),
            )

            self._init_weights()

        def _init_weights(self) -> None:
            nn.init.trunc_normal_(self.pos_embed, std=0.02)
            nn.init.trunc_normal_(self.cls_token, std=0.02)
            for m in self.modules():
                if isinstance(m, nn.Linear):
                    nn.init.trunc_normal_(m.weight, std=0.02)
                    if m.bias is not None:
                        nn.init.zeros_(m.bias)
                elif isinstance(m, nn.LayerNorm):
                    nn.init.ones_(m.weight)
                    nn.init.zeros_(m.bias)

        def forward(
            self, x: "torch.Tensor"
        ) -> Tuple["torch.Tensor", "torch.Tensor"]:
            """
            Returns:
                class_logits : (B, num_classes)
                anomaly_score: (B, 1)  — value in [0, 1]
            """
            B = x.shape[0]

            # Patch embedding
            x = self.patch_embed(x)  # (B, num_patches, embed_dim)

            # Prepend CLS token
            cls = self.cls_token.expand(B, -1, -1)
            x = torch.cat([cls, x], dim=1)  # (B, num_patches+1, embed_dim)

            # Add positional embedding
            x = x + self.pos_embed
            x = self.pos_drop(x)

            # Transformer blocks
            for block in self.blocks:
                x = block(x)

            x = self.norm(x)
            cls_out = x[:, 0]  # CLS token output

            class_logits = self.head(cls_out)
            anomaly_score = self.anomaly_head(cls_out)

            return class_logits, anomaly_score


# ── LogVisionTransformer (inference wrapper) ──────────────────────


class LogVisionTransformer:
    """
    High-level wrapper around VisionTransformer for log anomaly detection.

    Handles:
        - Model loading / saving
        - Device management (CPU / CUDA)
        - Batch inference
        - Result interpretation

    Usage::

        vit = LogVisionTransformer()
        vit.load_weights("models/vit_anomaly.pt")  # optional
        result = vit.predict(image_tensor)
        # result = {"anomaly_score": 0.87, "anomaly_class": "LATERAL_MOVEMENT", ...}
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._cfg = self._settings.vit
        self._model: Optional["VisionTransformer"] = None
        self._device: str = "cpu"

        if _TORCH_AVAILABLE:
            self._device = (
                "cuda"
                if torch.cuda.is_available() and self._cfg.use_gpu
                else "cpu"
            )
            self._build_model()
        else:
            logger.warning("PyTorch unavailable — LogVisionTransformer in mock mode")

    def _build_model(self) -> None:
        """Instantiate the ViT model and move to device."""
        self._model = VisionTransformer(
            image_size=self._cfg.image_size,
            patch_size=self._cfg.patch_size,
            in_channels=3,
            num_classes=self._cfg.num_classes,
            embed_dim=self._cfg.embed_dim,
            num_heads=self._cfg.num_heads,
            num_layers=self._cfg.num_layers,
            mlp_ratio=4.0,
            dropout=self._cfg.dropout,
        ).to(self._device)
        self._model.eval()
        logger.info(
            "ViT model built: {}×{} image, {} patches, {} layers, device={}",
            self._cfg.image_size,
            self._cfg.image_size,
            (self._cfg.image_size // self._cfg.patch_size) ** 2,
            self._cfg.num_layers,
            self._device,
        )

    def load_weights(self, path: Optional[str] = None) -> bool:
        """
        Load pre-trained weights from disk.

        Returns True if weights were loaded successfully.
        """
        if not _TORCH_AVAILABLE or self._model is None:
            return False

        weight_path = Path(path or self._cfg.model_path)
        if not weight_path.exists():
            logger.warning("ViT weights not found at {}. Using random init.", weight_path)
            return False

        try:
            state_dict = torch.load(weight_path, map_location=self._device)
            self._model.load_state_dict(state_dict, strict=False)
            logger.info("Loaded ViT weights from {}", weight_path)
            return True
        except Exception as exc:
            logger.error("Failed to load ViT weights: {}", exc)
            return False

    def save_weights(self, path: str) -> None:
        """Save model weights to disk."""
        if not _TORCH_AVAILABLE or self._model is None:
            return
        torch.save(self._model.state_dict(), path)
        logger.info("ViT weights saved to {}", path)

    def predict(self, image_tensor: Any) -> Dict[str, Any]:
        """
        Run inference on a single image tensor.

        Args:
            image_tensor: torch.Tensor of shape (3, H, W) or (1, 3, H, W)

        Returns:
            dict with keys:
                anomaly_score  : float in [0, 1]
                anomaly_class  : str
                class_probs    : dict[str, float]
                is_anomalous   : bool
        """
        if not _TORCH_AVAILABLE or self._model is None:
            return self._mock_predict()

        import torch

        with torch.no_grad():
            if image_tensor.dim() == 3:
                image_tensor = image_tensor.unsqueeze(0)  # add batch dim

            image_tensor = image_tensor.to(self._device)
            class_logits, anomaly_score = self._model(image_tensor)

            probs = F.softmax(class_logits, dim=-1).squeeze(0).cpu().numpy()
            score = anomaly_score.squeeze().item()
            class_idx = int(probs.argmax())

        class_probs = {
            ANOMALY_CLASSES[i]: float(probs[i])
            for i in range(len(ANOMALY_CLASSES))
        }

        return {
            "anomaly_score": round(score, 4),
            "anomaly_class": ANOMALY_CLASSES[class_idx],
            "class_probs": class_probs,
            "is_anomalous": score >= self._settings.detection.anomaly_threshold,
        }

    def predict_batch(self, tensors: List[Any]) -> List[Dict[str, Any]]:
        """Run inference on a batch of image tensors."""
        if not _TORCH_AVAILABLE or self._model is None:
            return [self._mock_predict() for _ in tensors]

        import torch

        batch = torch.stack(tensors).to(self._device)
        with torch.no_grad():
            class_logits, anomaly_scores = self._model(batch)
            probs_batch = F.softmax(class_logits, dim=-1).cpu().numpy()
            scores = anomaly_scores.squeeze(-1).cpu().numpy()

        results = []
        for i in range(len(tensors)):
            probs = probs_batch[i]
            score = float(scores[i])
            class_idx = int(probs.argmax())
            results.append({
                "anomaly_score": round(score, 4),
                "anomaly_class": ANOMALY_CLASSES[class_idx],
                "class_probs": {
                    ANOMALY_CLASSES[j]: float(probs[j])
                    for j in range(len(ANOMALY_CLASSES))
                },
                "is_anomalous": score >= self._settings.detection.anomaly_threshold,
            })
        return results

    def _mock_predict(self) -> Dict[str, Any]:
        """Return a mock prediction when PyTorch is unavailable."""
        import random
        score = random.uniform(0.0, 0.3)
        return {
            "anomaly_score": round(score, 4),
            "anomaly_class": "NORMAL",
            "class_probs": {c: 0.2 for c in ANOMALY_CLASSES},
            "is_anomalous": False,
        }

    @property
    def device(self) -> str:
        return self._device

    def parameter_count(self) -> int:
        """Return total number of model parameters."""
        if self._model is None:
            return 0
        return sum(p.numel() for p in self._model.parameters())
