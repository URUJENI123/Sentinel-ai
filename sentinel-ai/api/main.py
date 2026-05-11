"""
api/main.py
────────────
FastAPI REST + WebSocket interface for Sentinel AI.

Endpoints:
    GET  /health                          — Health check
    GET  /threats/active                  — List active threats
    GET  /threats/{id}                    — Get threat details
    POST /threats/{id}/mitigate           — Trigger mitigation
    GET  /graph/attack-path/{host}        — Get attack graph for host
    GET  /graph/blast-radius/{host}       — Calculate blast radius
    GET  /metrics                         — System metrics
    POST /simulation/start                — Start threat simulation
    GET  /simulation/scenarios            — List available scenarios
    WS   /ws/alerts                       — Real-time alert stream
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel, Field

from config.settings import get_settings
from simulation.threat_simulator import ThreatSimulator

try:
    from agents.orchestrator import ThreatOrchestrator
    _ORCHESTRATOR_AVAILABLE = True
except ImportError as _e:
    logger.warning("Orchestrator unavailable (missing deps: {}). Running in lite mode.", _e)
    ThreatOrchestrator = None  # type: ignore
    _ORCHESTRATOR_AVAILABLE = False

try:
    from detection.anomaly_detector import AnomalyAlert, AlertSeverity
except ImportError:
    AnomalyAlert = None  # type: ignore
    AlertSeverity = None  # type: ignore

# ── Global state ──────────────────────────────────────────────────

orchestrator: Optional[ThreatOrchestrator] = None
simulator: Optional[ThreatSimulator] = None
settings = get_settings()


# ── Lifecycle ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global orchestrator, simulator

    logger.info("Starting Sentinel AI API...")

    simulator = ThreatSimulator()

    if _ORCHESTRATOR_AVAILABLE:
        try:
            orchestrator = ThreatOrchestrator()
            await orchestrator.start()
        except Exception as exc:
            logger.warning("Orchestrator failed to start: {}. Running in simulation-only mode.", exc)
            orchestrator = None
    else:
        logger.info("Running in lite mode — simulation and detection endpoints available")

    logger.info("Sentinel AI API ready")
    yield

    logger.info("Shutting down Sentinel AI API...")
    if orchestrator:
        await orchestrator.stop()


# ── FastAPI app ───────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel AI",
    description="Autonomous Cyber Threat Hunter API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.get_cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request/Response models ───────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    components: Dict[str, str]


class MitigationRequest(BaseModel):
    action: str = Field(..., description="Mitigation action: block_ip, isolate_system, etc.")
    dry_run: bool = Field(default=True, description="If true, log action without executing")


class SimulationRequest(BaseModel):
    scenario: str = Field(..., description="Scenario name (e.g., 'brute_force_ssh')")
    intensity: float = Field(default=0.5, ge=0.0, le=1.0, description="Intensity 0.0-1.0")
    duration: Optional[int] = Field(default=None, description="Duration in seconds (overrides default)")


# ── Health & Status ───────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """System health check."""
    uptime = 0.0
    orc_status = "unavailable"
    if orchestrator:
        metrics = orchestrator.get_metrics()
        uptime = metrics.get("uptime_seconds", 0)
        orc_status = "running"

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=uptime,
        components={
            "orchestrator": orc_status,
            "simulator": "running",
            "mode": "lite" if not _ORCHESTRATOR_AVAILABLE else "full",
        },
    )


@app.get("/metrics")
async def get_metrics():
    """Get comprehensive system metrics."""
    if not orchestrator:
        return {
            "mode": "lite",
            "orchestrator": "unavailable",
            "simulator": "running",
            "active_simulations": len(simulator.get_active_simulations()) if simulator else 0,
        }
    return orchestrator.get_metrics()


# ── Threat Management ─────────────────────────────────────────────

@app.get("/threats/active")
async def get_active_threats():
    """List all active (non-closed) threats."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    return {"threats": orchestrator.get_active_threats()}


@app.get("/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get detailed information about a specific threat."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    threat = orchestrator.get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
    return threat


@app.post("/threats/{alert_id}/mitigate")
async def trigger_mitigation(alert_id: str, request: MitigationRequest):
    """Manually trigger a mitigation action for an alert."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    result = await orchestrator.trigger_mitigation(
        alert_id=alert_id,
        action=request.action,
        dry_run=request.dry_run,
    )

    if not result:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return result.to_dict()


# ── Attack Graph ──────────────────────────────────────────────────

@app.get("/graph/attack-path/{host_ip}")
async def get_attack_path(host_ip: str):
    """Get attack paths originating from or passing through a host."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    paths = await orchestrator._graph.get_attack_path(host_ip)
    return {"host_ip": host_ip, "paths": paths}


@app.get("/graph/blast-radius/{host_ip}")
async def get_blast_radius(host_ip: str):
    """Calculate the blast radius from a compromised host."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    radius = await orchestrator._graph.get_blast_radius(host_ip)
    return radius


@app.get("/graph/compromised-hosts")
async def get_compromised_hosts():
    """List all hosts marked as compromised in the graph."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    hosts = await orchestrator._graph.get_compromised_hosts()
    return {"hosts": hosts}


@app.get("/graph/technique-frequency")
async def get_technique_frequency():
    """Get MITRE techniques ordered by usage frequency."""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    techniques = await orchestrator._graph.get_technique_frequency()
    return {"techniques": techniques}


# ── Simulation ────────────────────────────────────────────────────

@app.get("/simulation/scenarios")
async def list_scenarios():
    """List available threat simulation scenarios."""
    if not simulator:
        raise HTTPException(status_code=503, detail="Simulator not initialized")
    return {"scenarios": simulator.list_scenarios()}


@app.get("/simulation/active")
async def get_active_simulations():
    """List currently running simulations."""
    if not simulator:
        raise HTTPException(status_code=503, detail="Simulator not initialized")
    return {"simulations": simulator.get_active_simulations()}


@app.post("/simulation/start")
async def start_simulation(request: SimulationRequest):
    """Start a threat simulation scenario."""
    if not simulator or not orchestrator:
        raise HTTPException(status_code=503, detail="Services not initialized")

    # Run simulation in background and feed events to orchestrator
    async def run_sim():
        try:
            async for event in simulator.run_scenario(
                request.scenario,
                intensity=request.intensity,
                duration_override=request.duration,
            ):
                # Feed simulated events to the detection pipeline
                await orchestrator._process_event(event)
        except Exception as exc:
            logger.error("Simulation error: {}", exc)

    asyncio.create_task(run_sim())

    return {
        "status": "started",
        "scenario": request.scenario,
        "intensity": request.intensity,
        "message": "Simulation running in background",
    }


@app.post("/simulation/stop/{simulation_id}")
async def stop_simulation(simulation_id: str):
    """Stop a running simulation."""
    if not simulator:
        raise HTTPException(status_code=503, detail="Simulator not initialized")

    success = simulator.stop_simulation(simulation_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Simulation {simulation_id} not found")

    return {"status": "stopped", "simulation_id": simulation_id}


# ── WebSocket: Real-time alerts ──────────────────────────────────

class ConnectionManager:
    """Manages WebSocket connections for alert streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Total: {}", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info("WebSocket client disconnected. Total: {}", len(self.active_connections))

    async def broadcast(self, message: str):
        """Broadcast a message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as exc:
                logger.debug("WebSocket send error: {}", exc)


manager = ConnectionManager()


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    Subscribes to Redis pub/sub channel and forwards alerts to clients.
    """
    await manager.connect(websocket)

    # Subscribe to Redis alert channel
    redis_client = aioredis.from_url(
        settings.redis.url,
        password=settings.redis.password or None,
        db=settings.redis.db,
        decode_responses=True,
    )
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("sentinel:alerts")

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        logger.error("WebSocket error: {}", exc)
        manager.disconnect(websocket)
    finally:
        await pubsub.unsubscribe("sentinel:alerts")
        await redis_client.aclose()


# ── Error handlers ────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("Unhandled exception: {}", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


# ── Entry point ───────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        reload=False,
        log_level=settings.log_level.lower(),
    )
