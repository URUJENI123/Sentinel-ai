"""
main.py
────────
Sentinel AI — main entry point.

Modes:
    api         Start the FastAPI server (default)
    train       Train the RL agent
    simulate    Run a threat simulation scenario
    detect      Run detection pipeline only (no API)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from loguru import logger


def setup_logging(log_level: str, log_file: str) -> None:
    """Configure loguru logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{line}</cyan> — <level>{message}</level>",
        colorize=True,
    )
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level=log_level,
            rotation="100 MB",
            retention="30 days",
            compression="gz",
        )


async def run_api() -> None:
    """Start the FastAPI server."""
    import uvicorn
    from config.settings import get_settings

    settings = get_settings()
    config = uvicorn.Config(
        "api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        workers=1,  # Use 1 worker for async; scale with gunicorn in prod
        log_level=settings.log_level.lower(),
        access_log=True,
    )
    server = uvicorn.Server(config)
    await server.serve()


async def run_train(timesteps: int, save_path: str | None) -> None:
    """Train the RL mitigation agent."""
    from agents.rl_agent import RLMitigationAgent

    logger.info("Starting RL agent training for {} timesteps", timesteps)
    agent = RLMitigationAgent()
    agent.train(timesteps=timesteps, save_path=save_path)
    logger.info("Training complete")


async def run_simulate(scenario: str, intensity: float, duration: int | None) -> None:
    """Run a threat simulation and print generated events."""
    from simulation.threat_simulator import ThreatSimulator

    sim = ThreatSimulator()
    available = [s["name"] for s in sim.list_scenarios()]

    if scenario not in available:
        logger.error("Unknown scenario: {}. Available: {}", scenario, available)
        sys.exit(1)

    logger.info("Running simulation: scenario={} intensity={}", scenario, intensity)
    count = 0
    async for event in sim.run_scenario(scenario, intensity=intensity, duration_override=duration):
        logger.info("Event: type={} severity={} src={}", 
                    event.get("event_type"), event.get("severity"), event.get("source_ip"))
        count += 1

    logger.info("Simulation complete: {} events generated", count)


async def run_detect() -> None:
    """Run the detection pipeline without the API server."""
    from ingestion.pipeline import IngestionPipeline
    from detection.anomaly_detector import AnomalyDetector

    pipeline = IngestionPipeline()
    detector = AnomalyDetector()

    await pipeline.start()
    logger.info("Detection pipeline running (Ctrl+C to stop)")

    try:
        async for event in pipeline.stream_events():
            alerts = detector.process_batch([event])
            for alert in alerts:
                logger.warning(
                    "ALERT: severity={} score={:.3f} class={} src={}",
                    alert.severity.value,
                    alert.composite_score,
                    alert.anomaly_class,
                    alert.source_ip,
                )
    except KeyboardInterrupt:
        pass
    finally:
        await pipeline.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel AI — Autonomous Cyber Threat Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py api                          # Start API server
  python main.py train --timesteps 200000     # Train RL agent
  python main.py simulate --scenario brute_force_ssh --intensity 0.8
  python main.py detect                       # Detection pipeline only
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # API command
    subparsers.add_parser("api", help="Start the FastAPI server")

    # Train command
    train_parser = subparsers.add_parser("train", help="Train the RL agent")
    train_parser.add_argument("--timesteps", type=int, default=100_000)
    train_parser.add_argument("--save-path", type=str, default=None)

    # Simulate command
    sim_parser = subparsers.add_parser("simulate", help="Run a threat simulation")
    sim_parser.add_argument(
        "--scenario",
        type=str,
        default="brute_force_ssh",
        choices=[
            "apt_lateral_movement", "brute_force_ssh", "data_exfiltration",
            "ransomware", "insider_threat", "port_scan_recon", "web_exploit",
        ],
    )
    sim_parser.add_argument("--intensity", type=float, default=0.5)
    sim_parser.add_argument("--duration", type=int, default=None)

    # Detect command
    subparsers.add_parser("detect", help="Run detection pipeline only")

    # Global options
    parser.add_argument("--log-level", default=None, help="Override log level")

    args = parser.parse_args()

    # Load settings and configure logging
    from config.settings import get_settings
    settings = get_settings()
    log_level = args.log_level or settings.log_level
    setup_logging(log_level, settings.log_file)

    # Default to API if no command given
    command = args.command or "api"

    logger.info("Sentinel AI starting — command={}", command)

    if command == "api":
        asyncio.run(run_api())
    elif command == "train":
        asyncio.run(run_train(args.timesteps, args.save_path))
    elif command == "simulate":
        asyncio.run(run_simulate(args.scenario, args.intensity, args.duration))
    elif command == "detect":
        asyncio.run(run_detect())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
