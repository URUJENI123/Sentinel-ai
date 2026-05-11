"""
config/settings.py
──────────────────
Centralised configuration for Sentinel AI loaded from environment
variables / .env file via Pydantic BaseSettings.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ElasticsearchSettings(BaseSettings):
    """Elasticsearch connection and index configuration."""

    model_config = SettingsConfigDict(env_prefix="ES_", extra="ignore")

    url: str = Field(default="http://localhost:9200", alias="ELASTICSEARCH_URL")
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    index_syslog: str = Field(default="sentinel-syslog")
    index_auth: str = Field(default="sentinel-auth")
    index_network: str = Field(default="sentinel-network")
    index_app: str = Field(default="sentinel-application")
    request_timeout: int = Field(default=30)
    max_retries: int = Field(default=3)
    retry_on_timeout: bool = Field(default=True)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class Neo4jSettings(BaseSettings):
    """Neo4j graph database configuration."""

    uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    user: str = Field(default="neo4j", alias="NEO4J_USER")
    password: str = Field(default="sentinel_password", alias="NEO4J_PASSWORD")
    max_connection_pool_size: int = Field(default=50)
    connection_timeout: int = Field(default=30)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class RedisSettings(BaseSettings):
    """Redis queue and cache configuration."""

    url: str = Field(default="redis://localhost:6379", alias="REDIS_URL")
    password: Optional[str] = Field(default=None, alias="REDIS_PASSWORD")
    db: int = Field(default=0, alias="REDIS_DB")
    max_connections: int = Field(default=20)
    socket_timeout: int = Field(default=5)
    queue_name: str = Field(default="sentinel:events")
    alert_channel: str = Field(default="sentinel:alerts")

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class LLMSettings(BaseSettings):
    """LLM provider configuration."""

    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    primary_model: str = Field(default="gpt-4o")
    fallback_model: str = Field(default="claude-3-5-sonnet-20241022")
    temperature: float = Field(default=0.1)
    max_tokens: int = Field(default=4096)
    request_timeout: int = Field(default=60)
    max_retries: int = Field(default=3)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class DetectionSettings(BaseSettings):
    """Anomaly detection thresholds and model configuration."""

    anomaly_threshold: float = Field(default=0.7, alias="ANOMALY_THRESHOLD")
    critical_threshold: float = Field(default=0.92, alias="CRITICAL_THRESHOLD")
    high_threshold: float = Field(default=0.80, alias="HIGH_THRESHOLD")
    medium_threshold: float = Field(default=0.65, alias="MEDIUM_THRESHOLD")
    low_threshold: float = Field(default=0.40, alias="LOW_THRESHOLD")

    # Isolation Forest
    isolation_forest_contamination: float = Field(default=0.05)
    isolation_forest_n_estimators: int = Field(default=100)

    # Z-score
    zscore_window: int = Field(default=100)
    zscore_threshold: float = Field(default=3.0)

    # Baseline profiling
    baseline_window_hours: int = Field(default=24)
    min_baseline_samples: int = Field(default=50)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class VisionTransformerSettings(BaseSettings):
    """Vision Transformer model configuration."""

    model_path: str = Field(default="models/vit_anomaly.pt", alias="VIT_MODEL_PATH")
    image_size: int = Field(default=224, alias="VIT_IMAGE_SIZE")
    patch_size: int = Field(default=16, alias="VIT_PATCH_SIZE")
    num_classes: int = Field(default=5, alias="VIT_NUM_CLASSES")
    embed_dim: int = Field(default=768, alias="VIT_EMBED_DIM")
    num_heads: int = Field(default=12, alias="VIT_NUM_HEADS")
    num_layers: int = Field(default=12, alias="VIT_NUM_LAYERS")
    mlp_ratio: float = Field(default=4.0)
    dropout: float = Field(default=0.1)
    use_gpu: bool = Field(default=True)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class RLSettings(BaseSettings):
    """Reinforcement learning agent configuration."""

    model_path: str = Field(default="models/rl_agent.zip", alias="RL_MODEL_PATH")
    training_timesteps: int = Field(default=100_000, alias="RL_TRAINING_TIMESTEPS")
    learning_rate: float = Field(default=3e-4, alias="RL_LEARNING_RATE")
    n_steps: int = Field(default=2048, alias="RL_N_STEPS")
    batch_size: int = Field(default=64, alias="RL_BATCH_SIZE")
    n_epochs: int = Field(default=10, alias="RL_N_EPOCHS")
    gamma: float = Field(default=0.99, alias="RL_GAMMA")
    # Reward shaping
    reward_true_positive: float = Field(default=10.0)
    reward_false_positive: float = Field(default=-5.0)
    reward_missed_threat: float = Field(default=-20.0)
    reward_do_nothing: float = Field(default=-1.0)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class IngestionSettings(BaseSettings):
    """Data ingestion configuration."""

    batch_size: int = Field(default=100, alias="INGESTION_BATCH_SIZE")
    poll_interval: int = Field(default=5, alias="INGESTION_POLL_INTERVAL")
    packet_interface: str = Field(default="eth0", alias="PACKET_CAPTURE_INTERFACE")
    packet_filter: str = Field(default="", alias="PACKET_CAPTURE_FILTER")
    max_queue_size: int = Field(default=10_000)

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class APISettings(BaseSettings):
    """FastAPI server configuration."""

    host: str = Field(default="0.0.0.0", alias="API_HOST")
    port: int = Field(default=8000, alias="API_PORT")
    workers: int = Field(default=4, alias="API_WORKERS")
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5601",
        alias="CORS_ORIGINS",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list) -> str:
        if isinstance(v, list):
            return ",".join(v)
        return v or "http://localhost:3000"

    def get_cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class AlertingSettings(BaseSettings):
    """SOC alerting and notification configuration."""

    soc_webhook_url: Optional[str] = Field(default=None, alias="SOC_WEBHOOK_URL")
    soc_email: Optional[str] = Field(default=None, alias="SOC_EMAIL")
    pagerduty_key: Optional[str] = Field(default=None, alias="PAGERDUTY_INTEGRATION_KEY")

    @field_validator("soc_webhook_url", "soc_email", "pagerduty_key", mode="before")
    @classmethod
    def empty_str_to_none(cls, v: str | None) -> str | None:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        extra="ignore",
        populate_by_name=True,
    )


class Settings(BaseSettings):
    """
    Root settings object that aggregates all sub-configurations.
    Loaded once and cached via get_settings().
    """

    # Operational flags
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/sentinel.log", alias="LOG_FILE")
    simulation_mode: bool = Field(default=False, alias="SIMULATION_MODE")
    dry_run: bool = Field(default=True, alias="DRY_RUN")

    # Sub-configs (instantiated with defaults; override via env)
    elasticsearch: ElasticsearchSettings = Field(default_factory=ElasticsearchSettings)
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    vit: VisionTransformerSettings = Field(default_factory=VisionTransformerSettings)
    rl: RLSettings = Field(default_factory=RLSettings)
    ingestion: IngestionSettings = Field(default_factory=IngestionSettings)
    api: APISettings = Field(default_factory=APISettings)
    alerting: AlertingSettings = Field(default_factory=AlertingSettings)

    # Paths
    base_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent)
    models_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "models")
    prompts_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent / "prompts")
    mitre_config_path: Path = Field(
        default_factory=lambda: Path(__file__).parent / "mitre_attack.json"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()
