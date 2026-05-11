"""
ingestion/log_ingester.py
─────────────────────────
Pulls logs from Elasticsearch indices, normalises them to a common
schema, and queues them for downstream processing.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional

from elasticsearch import AsyncElasticsearch, ConnectionError, TransportError
from loguru import logger
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config.settings import get_settings

# ── Normalised log schema ─────────────────────────────────────────

NormalisedLog = Dict[str, Any]

SEVERITY_MAP: Dict[str, int] = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "warn": 3,
    "error": 4,
    "critical": 5,
    "alert": 6,
    "emergency": 7,
}


def _normalise_severity(raw: Any) -> str:
    """Convert various severity representations to a canonical string."""
    if isinstance(raw, int):
        levels = ["DEBUG", "INFO", "NOTICE", "WARNING", "WARNING", "ERROR", "CRITICAL", "ALERT"]
        return levels[min(raw, len(levels) - 1)]
    if isinstance(raw, str):
        return raw.upper()
    return "INFO"


def _extract_ip(doc: Dict[str, Any], field_candidates: List[str]) -> Optional[str]:
    """Try multiple field names to extract an IP address."""
    for field in field_candidates:
        value = doc.get(field)
        if value:
            return str(value)
    return None


def normalise_log(raw_doc: Dict[str, Any], index: str) -> NormalisedLog:
    """
    Convert a raw Elasticsearch document to the Sentinel normalised schema.

    Schema:
        timestamp   : ISO-8601 UTC string
        source_ip   : str | None
        dest_ip     : str | None
        event_type  : str
        raw_message : str
        severity    : str  (DEBUG / INFO / WARNING / ERROR / CRITICAL)
        index       : str  (originating ES index)
        host        : str | None
        user        : str | None
        process     : str | None
        extra       : dict (remaining fields)
    """
    source = raw_doc.get("_source", raw_doc)

    # Timestamp
    ts_raw = (
        source.get("@timestamp")
        or source.get("timestamp")
        or source.get("time")
        or datetime.now(timezone.utc).isoformat()
    )

    # IPs
    src_ip = _extract_ip(source, ["source.ip", "src_ip", "client.ip", "host.ip"])
    dst_ip = _extract_ip(source, ["destination.ip", "dst_ip", "server.ip"])

    # Event type
    event_type = (
        source.get("event.action")
        or source.get("event_type")
        or source.get("type")
        or "generic"
    )

    # Raw message
    raw_message = (
        source.get("message")
        or source.get("log.original")
        or source.get("raw")
        or str(source)
    )

    # Severity
    severity_raw = (
        source.get("log.level")
        or source.get("severity")
        or source.get("level")
        or "INFO"
    )
    severity = _normalise_severity(severity_raw)

    # Optional enrichment fields
    host = source.get("host.name") or source.get("hostname") or source.get("host")
    user = source.get("user.name") or source.get("user") or source.get("username")
    process = source.get("process.name") or source.get("process") or source.get("program")

    # Remaining fields as extra context
    known_keys = {
        "@timestamp", "timestamp", "time", "source.ip", "src_ip", "client.ip",
        "destination.ip", "dst_ip", "server.ip", "event.action", "event_type",
        "type", "message", "log.original", "raw", "log.level", "severity",
        "level", "host.name", "hostname", "host", "user.name", "user",
        "username", "process.name", "process", "program",
    }
    extra = {k: v for k, v in source.items() if k not in known_keys}

    return {
        "timestamp": ts_raw,
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "event_type": str(event_type),
        "raw_message": str(raw_message)[:4096],  # cap at 4 KB
        "severity": severity,
        "index": index,
        "host": str(host) if host else None,
        "user": str(user) if user else None,
        "process": str(process) if process else None,
        "extra": extra,
    }


# ── LogIngester ───────────────────────────────────────────────────

class LogIngester:
    """
    Connects to Elasticsearch, pulls logs from multiple indices,
    normalises them, and yields batches for downstream processing.

    Usage::

        ingester = LogIngester()
        await ingester.connect()
        async for batch in ingester.stream_logs():
            process(batch)
        await ingester.close()
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._es_cfg = self._settings.elasticsearch
        self._client: Optional[AsyncElasticsearch] = None
        self._indices: List[str] = [
            self._es_cfg.index_syslog,
            self._es_cfg.index_auth,
            self._es_cfg.index_network,
            self._es_cfg.index_app,
        ]
        self._last_timestamps: Dict[str, str] = {}
        self._batch_size = self._settings.ingestion.batch_size
        self._total_ingested: int = 0

    # ── Connection management ─────────────────────────────────────

    async def connect(self) -> None:
        """Establish connection to Elasticsearch with retry logic."""
        es_kwargs: Dict[str, Any] = {
            "hosts": [self._es_cfg.url],
            "request_timeout": self._es_cfg.request_timeout,
            "retry_on_timeout": self._es_cfg.retry_on_timeout,
            "max_retries": self._es_cfg.max_retries,
        }
        if self._es_cfg.username and self._es_cfg.password:
            es_kwargs["http_auth"] = (self._es_cfg.username, self._es_cfg.password)

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type((ConnectionError, TransportError)),
            reraise=True,
        ):
            with attempt:
                self._client = AsyncElasticsearch(**es_kwargs)
                info = await self._client.info()
                logger.info(
                    "Connected to Elasticsearch cluster '{}' version {}",
                    info["cluster_name"],
                    info["version"]["number"],
                )

    async def close(self) -> None:
        """Close the Elasticsearch connection."""
        if self._client:
            await self._client.close()
            logger.info("Elasticsearch connection closed.")

    # ── Index management ──────────────────────────────────────────

    async def ensure_indices(self) -> None:
        """Create indices with appropriate mappings if they don't exist."""
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "raw_message": {"type": "text"},
                    "host": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "process": {"type": "keyword"},
                }
            }
        }
        for index in self._indices:
            exists = await self._client.indices.exists(index=index)
            if not exists:
                await self._client.indices.create(index=index, body=mapping)
                logger.info("Created Elasticsearch index: {}", index)

    # ── Log fetching ──────────────────────────────────────────────

    async def _fetch_from_index(
        self, index: str, after_timestamp: Optional[str] = None
    ) -> List[NormalisedLog]:
        """
        Fetch a batch of logs from a single index, optionally filtered
        to only documents newer than `after_timestamp`.
        """
        query: Dict[str, Any] = {"match_all": {}}
        if after_timestamp:
            query = {
                "range": {
                    "@timestamp": {"gt": after_timestamp}
                }
            }

        try:
            response = await self._client.search(
                index=index,
                body={
                    "query": query,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "size": self._batch_size,
                },
                ignore_unavailable=True,
            )
        except Exception as exc:
            logger.warning("Failed to fetch from index {}: {}", index, exc)
            return []

        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return []

        normalised = [normalise_log(hit, index) for hit in hits]

        # Track the latest timestamp for incremental polling
        last_ts = hits[-1].get("_source", {}).get("@timestamp")
        if last_ts:
            self._last_timestamps[index] = last_ts

        return normalised

    async def fetch_batch(self) -> List[NormalisedLog]:
        """
        Fetch one batch of logs from all configured indices.
        Returns a combined, time-sorted list.
        """
        if not self._client:
            raise RuntimeError("LogIngester not connected. Call connect() first.")

        tasks = [
            self._fetch_from_index(index, self._last_timestamps.get(index))
            for index in self._indices
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        combined: List[NormalisedLog] = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Index fetch error: {}", result)
                continue
            combined.extend(result)

        # Sort by timestamp
        combined.sort(key=lambda x: x.get("timestamp", ""))
        self._total_ingested += len(combined)
        return combined

    async def stream_logs(
        self, poll_interval: Optional[int] = None
    ) -> AsyncIterator[List[NormalisedLog]]:
        """
        Continuously poll all indices and yield batches of normalised logs.

        Args:
            poll_interval: Seconds between polls. Defaults to settings value.
        """
        interval = poll_interval or self._settings.ingestion.poll_interval
        logger.info(
            "Starting log stream from {} indices, poll interval={}s",
            len(self._indices),
            interval,
        )
        while True:
            try:
                batch = await self.fetch_batch()
                if batch:
                    logger.debug("Fetched {} logs from Elasticsearch", len(batch))
                    yield batch
                await asyncio.sleep(interval)
            except Exception as exc:
                logger.error("Error during log streaming: {}", exc)
                await asyncio.sleep(interval * 2)

    # ── Metrics ───────────────────────────────────────────────────

    @property
    def total_ingested(self) -> int:
        """Total number of logs ingested since startup."""
        return self._total_ingested

    def get_metrics(self) -> Dict[str, Any]:
        """Return ingestion metrics."""
        return {
            "total_ingested": self._total_ingested,
            "indices": self._indices,
            "last_timestamps": self._last_timestamps,
        }
