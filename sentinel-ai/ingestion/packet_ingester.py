"""
ingestion/packet_ingester.py
─────────────────────────────
Captures live network packets (or reads PCAPs) using Scapy/PyShark,
extracts features, detects basic anomalies, and streams events to
the processing queue.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Set

from loguru import logger

from config.settings import get_settings

# ── Data models ───────────────────────────────────────────────────


@dataclass
class PacketFeatures:
    """Normalised feature set extracted from a single packet."""

    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str          # TCP / UDP / ICMP / OTHER
    src_port: Optional[int]
    dst_port: Optional[int]
    payload_size: int
    flags: List[str]       # TCP flags: SYN, ACK, FIN, RST, PSH, URG
    ttl: Optional[int]
    is_anomalous: bool = False
    anomaly_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "payload_size": self.payload_size,
            "flags": self.flags,
            "ttl": self.ttl,
            "is_anomalous": self.is_anomalous,
            "anomaly_type": self.anomaly_type,
            "event_type": "network_packet",
            "severity": "HIGH" if self.is_anomalous else "INFO",
        }


# ── Port scan tracker ─────────────────────────────────────────────


@dataclass
class PortScanTracker:
    """
    Tracks per-source-IP port access patterns to detect port scans.
    Uses a sliding time window.
    """

    window_seconds: int = 60
    threshold: int = 20  # distinct ports within window = scan

    _records: Dict[str, Deque[tuple]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=500))
    )

    def record(self, src_ip: str, dst_port: int) -> bool:
        """
        Record a connection attempt. Returns True if a port scan is detected.
        """
        now = time.monotonic()
        self._records[src_ip].append((now, dst_port))

        # Prune old entries
        cutoff = now - self.window_seconds
        while self._records[src_ip] and self._records[src_ip][0][0] < cutoff:
            self._records[src_ip].popleft()

        distinct_ports: Set[int] = {p for _, p in self._records[src_ip]}
        return len(distinct_ports) >= self.threshold


# ── Large transfer tracker ────────────────────────────────────────


@dataclass
class TransferTracker:
    """Tracks cumulative bytes per (src_ip, dst_ip) pair."""

    window_seconds: int = 300          # 5-minute window
    threshold_bytes: int = 50_000_000  # 50 MB

    _records: Dict[tuple, Deque[tuple]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=10_000))
    )

    def record(self, src_ip: str, dst_ip: str, size: int) -> bool:
        """Returns True if cumulative transfer exceeds threshold."""
        now = time.monotonic()
        key = (src_ip, dst_ip)
        self._records[key].append((now, size))

        cutoff = now - self.window_seconds
        while self._records[key] and self._records[key][0][0] < cutoff:
            self._records[key].popleft()

        total = sum(s for _, s in self._records[key])
        return total >= self.threshold_bytes


# ── PacketIngester ────────────────────────────────────────────────


class PacketIngester:
    """
    Captures network packets from a live interface or PCAP file,
    extracts features, detects anomalies, and streams events.

    Anomaly detection:
        - Port scans: ≥20 distinct destination ports from one source in 60s
        - Unusual protocols: non-TCP/UDP/ICMP traffic
        - Large transfers: >50 MB between a pair in 5 minutes
        - Suspicious ports: traffic to known malicious/unusual ports

    Usage::

        ingester = PacketIngester()
        await ingester.start(callback=my_handler)
        # ... later ...
        await ingester.stop()
    """

    SUSPICIOUS_PORTS: Set[int] = {
        4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669,  # common RAT/C2
        9001, 9030,  # Tor
        8080, 8443,  # common proxy/C2
    }

    UNUSUAL_PROTOCOLS: Set[str] = {"GRE", "ESP", "AH", "OSPF", "EIGRP"}

    def __init__(self) -> None:
        self._settings = get_settings()
        self._cfg = self._settings.ingestion
        self._port_scan_tracker = PortScanTracker()
        self._transfer_tracker = TransferTracker()
        self._running = False
        self._total_captured: int = 0
        self._total_anomalies: int = 0
        self._callback: Optional[Callable[[PacketFeatures], None]] = None
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=self._settings.ingestion.max_queue_size
        )

    # ── Packet parsing ────────────────────────────────────────────

    def _parse_scapy_packet(self, pkt: Any) -> Optional[PacketFeatures]:
        """Extract features from a Scapy packet object."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ttl = pkt[IP].ttl
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                ttl = pkt[IPv6].hlim
            else:
                return None  # Non-IP packet

            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            flags: List[str] = []
            protocol = "OTHER"

            if TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flag_int = pkt[TCP].flags
                flag_names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
                              0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
                flags = [name for bit, name in flag_names.items() if flag_int & bit]
            elif UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                protocol = "ICMP"

            payload_size = len(pkt.payload) if hasattr(pkt, "payload") else 0

            return PacketFeatures(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                payload_size=payload_size,
                flags=flags,
                ttl=ttl,
            )
        except Exception as exc:
            logger.debug("Packet parse error: {}", exc)
            return None

    # ── Anomaly detection ─────────────────────────────────────────

    def _detect_anomalies(self, features: PacketFeatures) -> PacketFeatures:
        """Apply heuristic anomaly checks and annotate the features object."""

        # 1. Port scan detection
        if features.dst_port and self._port_scan_tracker.record(
            features.src_ip, features.dst_port
        ):
            features.is_anomalous = True
            features.anomaly_type = "PORT_SCAN"
            logger.warning("Port scan detected from {}", features.src_ip)

        # 2. Unusual protocol
        if features.protocol in self.UNUSUAL_PROTOCOLS:
            features.is_anomalous = True
            features.anomaly_type = "UNUSUAL_PROTOCOL"
            logger.warning(
                "Unusual protocol {} from {}", features.protocol, features.src_ip
            )

        # 3. Large transfer
        if self._transfer_tracker.record(
            features.src_ip, features.dst_ip, features.payload_size
        ):
            features.is_anomalous = True
            features.anomaly_type = "LARGE_TRANSFER"
            logger.warning(
                "Large transfer detected: {} -> {}", features.src_ip, features.dst_ip
            )

        # 4. Suspicious destination port
        if features.dst_port and features.dst_port in self.SUSPICIOUS_PORTS:
            features.is_anomalous = True
            features.anomaly_type = "SUSPICIOUS_PORT"
            logger.warning(
                "Traffic to suspicious port {} from {}", features.dst_port, features.src_ip
            )

        # 5. SYN flood heuristic (many SYN, no ACK)
        if features.flags == ["SYN"] and features.payload_size == 0:
            if self._port_scan_tracker.record(features.src_ip, features.dst_port or 0):
                features.is_anomalous = True
                features.anomaly_type = "SYN_FLOOD"

        return features

    # ── Capture loop ──────────────────────────────────────────────

    async def _capture_live(self) -> None:
        """Capture packets from a live network interface using Scapy."""
        try:
            from scapy.all import AsyncSniffer

            def _handle(pkt: Any) -> None:
                features = self._parse_scapy_packet(pkt)
                if features:
                    features = self._detect_anomalies(features)
                    self._total_captured += 1
                    if features.is_anomalous:
                        self._total_anomalies += 1
                    try:
                        self._queue.put_nowait(features)
                    except asyncio.QueueFull:
                        logger.warning("Packet queue full, dropping packet")

            iface = self._cfg.packet_interface
            bpf_filter = self._cfg.packet_filter or None
            logger.info("Starting live capture on interface: {}", iface)

            sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf_filter,
                prn=_handle,
                store=False,
            )
            sniffer.start()

            while self._running:
                await asyncio.sleep(1)

            sniffer.stop()

        except ImportError:
            logger.warning("Scapy not available, falling back to simulation mode")
            await self._simulate_packets()
        except Exception as exc:
            logger.error("Live capture error: {}", exc)
            await self._simulate_packets()

    async def _simulate_packets(self) -> None:
        """Generate synthetic packet events for testing/simulation."""
        import random

        logger.info("Running packet ingester in simulation mode")
        sample_ips = [
            "192.168.1.10", "192.168.1.20", "10.0.0.5",
            "172.16.0.100", "203.0.113.50",
        ]
        protocols = ["TCP", "UDP", "ICMP"]

        while self._running:
            src = random.choice(sample_ips)
            dst = random.choice(sample_ips)
            if src == dst:
                await asyncio.sleep(0.1)
                continue

            features = PacketFeatures(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=src,
                dst_ip=dst,
                protocol=random.choice(protocols),
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 3389, 8080, 4444]),
                payload_size=random.randint(64, 1500),
                flags=random.choice([["SYN"], ["SYN", "ACK"], ["ACK"], ["FIN", "ACK"]]),
                ttl=random.randint(32, 128),
            )
            features = self._detect_anomalies(features)
            self._total_captured += 1
            if features.is_anomalous:
                self._total_anomalies += 1

            try:
                self._queue.put_nowait(features)
            except asyncio.QueueFull:
                pass

            await asyncio.sleep(0.05)  # ~20 packets/sec

    # ── Public API ────────────────────────────────────────────────

    async def start(
        self,
        callback: Optional[Callable[[PacketFeatures], None]] = None,
    ) -> None:
        """Start packet capture. Optionally provide a callback for each packet."""
        self._running = True
        self._callback = callback
        asyncio.create_task(self._capture_live())
        logger.info("PacketIngester started")

    async def stop(self) -> None:
        """Stop packet capture."""
        self._running = False
        logger.info("PacketIngester stopped. Captured: {}, Anomalies: {}",
                    self._total_captured, self._total_anomalies)

    async def get_packet(self, timeout: float = 1.0) -> Optional[PacketFeatures]:
        """Get the next packet from the queue (non-blocking with timeout)."""
        try:
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def stream_packets(self) -> Any:
        """Async generator that yields PacketFeatures objects."""
        while self._running:
            pkt = await self.get_packet()
            if pkt:
                yield pkt

    def get_metrics(self) -> Dict[str, Any]:
        """Return capture metrics."""
        return {
            "total_captured": self._total_captured,
            "total_anomalies": self._total_anomalies,
            "queue_size": self._queue.qsize(),
            "anomaly_rate": (
                self._total_anomalies / self._total_captured
                if self._total_captured > 0
                else 0.0
            ),
        }
