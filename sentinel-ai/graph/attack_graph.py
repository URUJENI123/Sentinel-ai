"""
graph/attack_graph.py
──────────────────────
Neo4j-backed attack graph for tracking lateral movement, blast radius,
and kill chain progression across the enterprise.

Node types:
    Host        — physical/virtual machine
    User        — user account
    Process     — running process
    Technique   — MITRE ATT&CK technique
    Alert       — anomaly alert

Relationship types:
    CONNECTED_TO    — network connection between hosts
    EXECUTED_ON     — process executed on host
    USED_BY         — technique used by threat actor
    TRIGGERED       — alert triggered by technique
    COMPROMISED     — host/user believed compromised
    LATERAL_MOVE    — lateral movement from host to host
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

try:
    from neo4j import AsyncGraphDatabase, AsyncDriver
    _NEO4J_AVAILABLE = True
except ImportError:
    _NEO4J_AVAILABLE = False
    logger.warning("neo4j driver not available — AttackGraph in mock mode")

from config.settings import get_settings


class AttackGraph:
    """
    Manages the Neo4j attack graph for Sentinel AI.

    Tracks:
        - Host compromise status and connections
        - Lateral movement paths
        - MITRE technique usage
        - Alert-to-technique mappings
        - Blast radius calculations

    Usage::

        graph = AttackGraph()
        await graph.connect()
        await graph.add_alert_node(alert_dict)
        path = await graph.get_attack_path("192.168.1.10")
        await graph.close()
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._cfg = self._settings.neo4j
        self._driver: Optional[Any] = None

    # ── Connection ────────────────────────────────────────────────

    async def connect(self) -> None:
        """Connect to Neo4j and create schema constraints."""
        if not _NEO4J_AVAILABLE:
            logger.warning("Neo4j unavailable — running in mock mode")
            return

        for attempt in range(5):
            try:
                self._driver = AsyncGraphDatabase.driver(
                    self._cfg.uri,
                    auth=(self._cfg.user, self._cfg.password),
                    max_connection_pool_size=self._cfg.max_connection_pool_size,
                    connection_timeout=self._cfg.connection_timeout,
                )
                await self._driver.verify_connectivity()
                logger.info("Connected to Neo4j at {}", self._cfg.uri)
                await self._create_schema()
                return
            except Exception as exc:
                import asyncio
                wait = 2 ** attempt
                logger.warning(
                    "Neo4j connection attempt {}/5 failed: {}. Retrying in {}s",
                    attempt + 1, exc, wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError("Failed to connect to Neo4j after 5 attempts")

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            await self._driver.close()
            logger.info("Neo4j connection closed")

    async def _create_schema(self) -> None:
        """Create uniqueness constraints and indexes."""
        constraints = [
            "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
            "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
            "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
            "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX host_compromised IF NOT EXISTS FOR (h:Host) ON (h.compromised)",
            "CREATE INDEX alert_severity IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
            "CREATE INDEX alert_timestamp IF NOT EXISTS FOR (a:Alert) ON (a.timestamp)",
        ]
        async with self._driver.session() as session:
            for stmt in constraints + indexes:
                try:
                    await session.run(stmt)
                except Exception as exc:
                    logger.debug("Schema statement skipped: {}", exc)
        logger.info("Neo4j schema initialised")

    # ── Node creation ─────────────────────────────────────────────

    async def upsert_host(
        self,
        ip: str,
        hostname: Optional[str] = None,
        compromised: bool = False,
        os_type: Optional[str] = None,
    ) -> None:
        """Create or update a Host node."""
        if not self._driver:
            return
        query = """
        MERGE (h:Host {ip: $ip})
        ON CREATE SET
            h.hostname = $hostname,
            h.os_type = $os_type,
            h.compromised = $compromised,
            h.first_seen = $now,
            h.last_seen = $now
        ON MATCH SET
            h.last_seen = $now,
            h.compromised = CASE WHEN $compromised THEN true ELSE h.compromised END,
            h.hostname = COALESCE($hostname, h.hostname)
        """
        async with self._driver.session() as session:
            await session.run(query, {
                "ip": ip,
                "hostname": hostname,
                "os_type": os_type,
                "compromised": compromised,
                "now": datetime.now(timezone.utc).isoformat(),
            })

    async def upsert_user(
        self,
        username: str,
        host_ip: Optional[str] = None,
        compromised: bool = False,
    ) -> None:
        """Create or update a User node, optionally linking to a Host."""
        if not self._driver:
            return
        async with self._driver.session() as session:
            await session.run("""
            MERGE (u:User {name: $username})
            ON CREATE SET u.compromised = $compromised, u.first_seen = $now
            ON MATCH SET u.last_seen = $now,
                         u.compromised = CASE WHEN $compromised THEN true ELSE u.compromised END
            """, {"username": username, "compromised": compromised,
                  "now": datetime.now(timezone.utc).isoformat()})

            if host_ip:
                await session.run("""
                MATCH (u:User {name: $username})
                MERGE (h:Host {ip: $host_ip})
                MERGE (u)-[:LOGGED_INTO {timestamp: $now}]->(h)
                """, {"username": username, "host_ip": host_ip,
                      "now": datetime.now(timezone.utc).isoformat()})

    async def upsert_technique(
        self,
        technique_id: str,
        name: str,
        tactic: str,
    ) -> None:
        """Create or update a MITRE Technique node."""
        if not self._driver:
            return
        async with self._driver.session() as session:
            await session.run("""
            MERGE (t:Technique {technique_id: $technique_id})
            ON CREATE SET t.name = $name, t.tactic = $tactic, t.first_seen = $now
            ON MATCH SET t.last_seen = $now, t.use_count = COALESCE(t.use_count, 0) + 1
            """, {"technique_id": technique_id, "name": name, "tactic": tactic,
                  "now": datetime.now(timezone.utc).isoformat()})

    async def add_alert_node(self, alert: Dict[str, Any]) -> None:
        """
        Add an Alert node and link it to related Host, User, and Technique nodes.
        """
        if not self._driver:
            return

        alert_id = alert.get("alert_id", str(uuid.uuid4()))
        source_ip = alert.get("source_ip")
        affected_hosts = alert.get("affected_hosts", [])
        anomaly_class = alert.get("anomaly_class", "UNKNOWN")

        async with self._driver.session() as session:
            # Create Alert node
            await session.run("""
            MERGE (a:Alert {alert_id: $alert_id})
            SET a.severity = $severity,
                a.composite_score = $score,
                a.anomaly_class = $anomaly_class,
                a.timestamp = $timestamp,
                a.description = $description
            """, {
                "alert_id": alert_id,
                "severity": alert.get("severity", "LOW"),
                "score": alert.get("composite_score", 0.0),
                "anomaly_class": anomaly_class,
                "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "description": alert.get("description", ""),
            })

            # Link to source host
            if source_ip:
                await self.upsert_host(source_ip, compromised=True)
                await session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MATCH (h:Host {ip: $ip})
                MERGE (a)-[:ORIGINATED_FROM]->(h)
                """, {"alert_id": alert_id, "ip": source_ip})

            # Link to affected hosts
            for host in affected_hosts:
                await self.upsert_host(host, compromised=True)
                await session.run("""
                MATCH (a:Alert {alert_id: $alert_id})
                MERGE (h:Host {ip: $host})
                MERGE (a)-[:AFFECTS]->(h)
                """, {"alert_id": alert_id, "host": host})

    async def add_lateral_movement(
        self,
        src_ip: str,
        dst_ip: str,
        technique_id: Optional[str] = None,
        confidence: float = 0.8,
    ) -> None:
        """Record a lateral movement edge between two hosts."""
        if not self._driver:
            return
        async with self._driver.session() as session:
            await session.run("""
            MERGE (src:Host {ip: $src_ip})
            MERGE (dst:Host {ip: $dst_ip})
            MERGE (src)-[r:LATERAL_MOVE]->(dst)
            SET r.technique_id = $technique_id,
                r.confidence = $confidence,
                r.timestamp = $now,
                r.count = COALESCE(r.count, 0) + 1
            """, {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "technique_id": technique_id,
                "confidence": confidence,
                "now": datetime.now(timezone.utc).isoformat(),
            })

    async def link_alert_to_technique(
        self,
        alert_id: str,
        technique_id: str,
        confidence: float,
    ) -> None:
        """Link an Alert to a MITRE Technique node."""
        if not self._driver:
            return
        async with self._driver.session() as session:
            await session.run("""
            MATCH (a:Alert {alert_id: $alert_id})
            MERGE (t:Technique {technique_id: $technique_id})
            MERGE (a)-[r:MAPS_TO]->(t)
            SET r.confidence = $confidence, r.timestamp = $now
            """, {
                "alert_id": alert_id,
                "technique_id": technique_id,
                "confidence": confidence,
                "now": datetime.now(timezone.utc).isoformat(),
            })

    # ── Queries ───────────────────────────────────────────────────

    async def get_attack_path(self, host_ip: str, max_depth: int = 6) -> List[Dict[str, Any]]:
        """
        Find all attack paths originating from or passing through a host.
        Returns a list of path segments.
        """
        if not self._driver:
            return []

        async with self._driver.session() as session:
            result = await session.run(f"""
            MATCH path = (src:Host {{ip: $ip}})-[:LATERAL_MOVE*1..{max_depth}]->(dst:Host)
            RETURN
                [node in nodes(path) | node.ip] AS hosts,
                [rel in relationships(path) | rel.technique_id] AS techniques,
                length(path) AS depth
            ORDER BY depth DESC
            LIMIT 20
            """, {"ip": host_ip})

            paths = []
            async for record in result:
                paths.append({
                    "hosts": record["hosts"],
                    "techniques": record["techniques"],
                    "depth": record["depth"],
                })
            return paths

    async def get_blast_radius(self, host_ip: str) -> Dict[str, Any]:
        """
        Calculate the blast radius from a compromised host.
        Returns counts of reachable hosts, users, and techniques.
        """
        if not self._driver:
            return {"host_ip": host_ip, "reachable_hosts": 0, "compromised_users": 0}

        async with self._driver.session() as session:
            result = await session.run("""
            MATCH (src:Host {ip: $ip})
            OPTIONAL MATCH (src)-[:LATERAL_MOVE*1..10]->(reachable:Host)
            OPTIONAL MATCH (reachable)<-[:LOGGED_INTO]-(u:User)
            OPTIONAL MATCH (a:Alert)-[:ORIGINATED_FROM]->(src)
            RETURN
                count(DISTINCT reachable) AS reachable_hosts,
                count(DISTINCT u) AS compromised_users,
                count(DISTINCT a) AS alert_count,
                collect(DISTINCT reachable.ip)[..10] AS reachable_ips
            """, {"ip": host_ip})

            record = await result.single()
            if not record:
                return {"host_ip": host_ip, "reachable_hosts": 0}

            return {
                "host_ip": host_ip,
                "reachable_hosts": record["reachable_hosts"],
                "compromised_users": record["compromised_users"],
                "alert_count": record["alert_count"],
                "reachable_ips": record["reachable_ips"],
            }

    async def get_active_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent high-severity alerts from the graph."""
        if not self._driver:
            return []

        async with self._driver.session() as session:
            result = await session.run("""
            MATCH (a:Alert)
            WHERE a.severity IN ['HIGH', 'CRITICAL']
            OPTIONAL MATCH (a)-[:ORIGINATED_FROM]->(h:Host)
            OPTIONAL MATCH (a)-[:MAPS_TO]->(t:Technique)
            RETURN
                a.alert_id AS alert_id,
                a.severity AS severity,
                a.composite_score AS score,
                a.anomaly_class AS anomaly_class,
                a.timestamp AS timestamp,
                a.description AS description,
                h.ip AS source_ip,
                collect(DISTINCT t.technique_id) AS techniques
            ORDER BY a.timestamp DESC
            LIMIT $limit
            """, {"limit": limit})

            threats = []
            async for record in result:
                threats.append(dict(record))
            return threats

    async def get_compromised_hosts(self) -> List[Dict[str, Any]]:
        """Return all hosts marked as compromised."""
        if not self._driver:
            return []

        async with self._driver.session() as session:
            result = await session.run("""
            MATCH (h:Host {compromised: true})
            OPTIONAL MATCH (h)<-[:LOGGED_INTO]-(u:User)
            RETURN
                h.ip AS ip,
                h.hostname AS hostname,
                h.last_seen AS last_seen,
                count(DISTINCT u) AS user_count
            ORDER BY h.last_seen DESC
            """)
            hosts = []
            async for record in result:
                hosts.append(dict(record))
            return hosts

    async def get_technique_frequency(self) -> List[Dict[str, Any]]:
        """Return techniques ordered by usage frequency."""
        if not self._driver:
            return []

        async with self._driver.session() as session:
            result = await session.run("""
            MATCH (t:Technique)
            OPTIONAL MATCH (a:Alert)-[:MAPS_TO]->(t)
            RETURN
                t.technique_id AS technique_id,
                t.name AS name,
                t.tactic AS tactic,
                count(a) AS alert_count,
                t.use_count AS use_count
            ORDER BY alert_count DESC
            LIMIT 20
            """)
            techniques = []
            async for record in result:
                techniques.append(dict(record))
            return techniques

    async def mark_host_contained(self, host_ip: str) -> None:
        """Mark a host as contained (isolated/remediated)."""
        if not self._driver:
            return
        async with self._driver.session() as session:
            await session.run("""
            MATCH (h:Host {ip: $ip})
            SET h.contained = true, h.contained_at = $now
            """, {"ip": host_ip, "now": datetime.now(timezone.utc).isoformat()})
