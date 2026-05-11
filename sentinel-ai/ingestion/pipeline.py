"""
ingestion/pipeline.py
──────────────────────
Orchestrates LogIngester and PacketIngester concurrently, buffers
events in Redis, and exposes ingestion metrics.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from loguru import logger

from config.settings import get_settings
from ingestion.log_ingester import LogIngester, NormalisedLog
from ingestion.packet_ingester import PacketFeatures, PacketIngester


# ── Metrics ───────────────────────────────────────────────────────


@dataclass
class PipelineMetrics:
    """Rolling metrics for the ingestion pipeline."""

    start_time: float = field(default_factory=time.monotonic)
    logs_ingested: int = 0
    packets_ingested: int = 0
    events_queued: int = 0
    events_processed: int = 0
    errors: int = 0
    last_event_time: Optional[float] = None

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def log_rate(self) -> float:
        """Logs per second."""
        uptime = self.uptime_seconds
        return self.logs_ingested / uptime if uptime > 0 else 0.0

    @property
    def packet_rate(self) -> float:
        """Packets per second."""
        uptime = self.uptime_seconds
        return self.packets_ingested / uptime if uptime > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uptime_seconds": round(self.uptime_seconds, 2),
            "logs_ingested": self.logs_ingested,
            "packets_ingested": self.packets_ingested,
            "events_queued": self.events_queued,
            "events_processed": self.events_processed,
            "errors": self.errors,
            "log_rate_per_sec": round(self.log_rate, 2),
            "packet_rate_per_sec": round(self.packet_rate, 2),
            "last_event_time": self.last_event_time,
        }


# ── IngestionPipeline ─────────────────────────────────────────────


class IngestionPipeline:
    """
    Coordinates log and packet ingestion, buffers events in Redis,
    and provides a unified async event stream for downstream consumers.

    Architecture:
        LogIngester  ──┐
                       ├──► Redis Queue ──► stream_events()
        PacketIngester ┘

    Usage::

        pipeline = IngestionPipeline()
        await pipeline.start()

        async for event in pipeline.stream_events():
            await process(event)

        await pipeline.stop()
    """

    QUEUE_KEY = "sentinel:events"
    METRICS_KEY = "sentinel:metrics:ingestion"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._redis_cfg = self._settings.redis
        self._redis: Optional[aioredis.Redis] = None
        self._log_ingester = LogIngester()
        self._packet_ingester = PacketIngester()
        self._metrics = PipelineMetrics()
        self._running = False
        self._tasks: List[asyncio.Task] = []

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Start all ingestion sources and the Redis buffer."""
        logger.info("Starting IngestionPipeline...")

        # Connect Redis
        await self._connect_redis()

        # Connect log ingester
        await self._log_ingester.connect()
        await self._log_ingester.ensure_indices()

        # Start packet ingester
        await self._packet_ingester.start()

        self._running = True

        # Launch concurrent ingestion tasks
        self._tasks = [
            asyncio.create_task(self._run_log_ingestion(), name="log-ingestion"),
            asyncio.create_task(self._run_packet_ingestion(), name="packet-ingestion"),
            asyncio.create_task(self._publish_metrics(), name="metrics-publisher"),
        ]

        logger.info("IngestionPipeline started with {} tasks", len(self._tasks))

    async def stop(self) -> None:
        """Gracefully stop all ingestion tasks."""
        logger.info("Stopping IngestionPipeline...")
        self._running = False

        for task in self._tasks:
            task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._packet_ingester.stop()
        await self._log_ingester.close()

        if self._redis:
            await self._redis.aclose()

        logger.info("IngestionPipeline stopped. Final metrics: {}", self._metrics.to_dict())

    # ── Redis connection ──────────────────────────────────────────

    async def _connect_redis(self) -> None:
        """Connect to Redis with retry logic."""
        for attempt in range(5):
            try:
                self._redis = aioredis.from_url(
                    self._redis_cfg.url,
                    password=self._redis_cfg.password or None,
                    db=self._redis_cfg.db,
                    max_connections=self._redis_cfg.max_connections,
                    socket_timeout=self._redis_cfg.socket_timeout,
                    decode_responses=True,
                )
                await self._redis.ping()
                logger.info("Connected to Redis at {}", self._redis_cfg.url)
                return
            except Exception as exc:
                wait = 2 ** attempt
                logger.warning(
                    "Redis connection attempt {}/5 failed: {}. Retrying in {}s",
                    attempt + 1, exc, wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError("Failed to connect to Redis after 5 attempts")

    # ── Ingestion workers ─────────────────────────────────────────

    async def _run_log_ingestion(self) -> None:
        """Continuously pull logs and push to Redis queue."""
        logger.info("Log ingestion worker started")
        async for batch in self._log_ingester.stream_logs():
            if not self._running:
                break
            for log in batch:
                await self._enqueue_event(log, source="log")
                self._metrics.logs_ingested += 1
            self._metrics.last_event_time = time.monotonic()

    async def _run_packet_ingestion(self) -> None:
        """Continuously pull packets and push to Redis queue."""
        logger.info("Packet ingestion worker started")
        async for pkt in self._packet_ingester.stream_packets():
            if not self._running:
                break
            await self._enqueue_event(pkt.to_dict(), source="packet")
            self._metrics.packets_ingested += 1
            self._metrics.last_event_time = time.monotonic()

    async def _enqueue_event(self, event: Dict[str, Any], source: str) -> None:
        """Serialise an event and push it to the Redis queue."""
        if not self._redis:
            return

        event["_source"] = source
        event["_ingested_at"] = datetime.now(timezone.utc).isoformat()

        try:
            serialised = json.dumps(event, default=str)
            await self._redis.lpush(self.QUEUE_KEY, serialised)
            self._metrics.events_queued += 1

            # Trim queue to prevent unbounded growth
            max_size = self._settings.ingestion.max_queue_size
            queue_len = await self._redis.llen(self.QUEUE_KEY)
            if queue_len > max_size:
                await self._redis.ltrim(self.QUEUE_KEY, 0, max_size - 1)
                logger.warning("Queue trimmed to {} events", max_size)

        except Exception as exc:
            self._metrics.errors += 1
            logger.error("Failed to enqueue event: {}", exc)

    # ── Event streaming ───────────────────────────────────────────

    async def stream_events(self, batch_size: int = 10) -> Any:
        """
        Async generator that yields batches of events from the Redis queue.
        Blocks until events are available.
        """
        if not self._redis:
            raise RuntimeError("Pipeline not started. Call start() first.")

        logger.info("Starting event stream from Redis queue")
        while self._running:
            try:
                # BRPOP blocks until an item is available (1s timeout)
                result = await self._redis.brpop(self.QUEUE_KEY, timeout=1)
                if result is None:
                    continue

                _, raw = result
                event = json.loads(raw)
                self._metrics.events_processed += 1
                yield event

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._metrics.errors += 1
                logger.error("Error reading from queue: {}", exc)
                await asyncio.sleep(0.5)

    async def get_queue_depth(self) -> int:
        """Return the current number of events in the Redis queue."""
        if not self._redis:
            return 0
        return await self._redis.llen(self.QUEUE_KEY)

    # ── Metrics publishing ────────────────────────────────────────

    async def _publish_metrics(self) -> None:
        """Periodically publish pipeline metrics to Redis."""
        while self._running:
            try:
                metrics = self.get_metrics()
                await self._redis.setex(
                    self.METRICS_KEY,
                    60,  # TTL 60 seconds
                    json.dumps(metrics, default=str),
                )
            except Exception as exc:
                logger.debug("Metrics publish error: {}", exc)
            await asyncio.sleep(10)

    def get_metrics(self) -> Dict[str, Any]:
        """Return combined pipeline metrics."""
        return {
            "pipeline": self._metrics.to_dict(),
            "log_ingester": self._log_ingester.get_metrics(),
            "packet_ingester": self._packet_ingester.get_metrics(),
        }
