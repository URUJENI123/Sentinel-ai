# Sentinel AI — Autonomous Cyber Threat Hunter

Sentinel AI is a production-grade autonomous cybersecurity system that combines Vision Transformers, multi-agent LLM reasoning, reinforcement learning, and graph-based attack analysis to detect, investigate, and respond to cyber threats in real time.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SENTINEL AI SYSTEM                          │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐
  │  Log Sources │    │ Network Tap  │    │   External Threat Intel  │
  │  (ES/Syslog) │    │  (PCAP/Live) │    │   (MITRE ATT&CK, OSINT)  │
  └──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘
         │                   │                         │
         ▼                   ▼                         │
  ┌──────────────────────────────────┐                 │
  │         INGESTION LAYER          │                 │
  │  ┌─────────────┐ ┌────────────┐  │                 │
  │  │LogIngester  │ │PacketIngest│  │                 │
  │  └──────┬──────┘ └─────┬──────┘  │                 │
  │         └──────┬────────┘         │                 │
  │          ┌─────▼──────┐           │                 │
  │          │  Pipeline  │           │                 │
  │          │ (Redis Q)  │           │                 │
  │          └─────┬──────┘           │                 │
  └────────────────┼─────────────────┘                 │
                   │                                   │
                   ▼                                   │
  ┌──────────────────────────────────┐                 │
  │         DETECTION LAYER          │                 │
  │  ┌──────────────────────────┐    │                 │
  │  │   LogHeatmapGenerator    │    │                 │
  │  │  (Logs → 224x224 Image)  │    │                 │
  │  └────────────┬─────────────┘    │                 │
  │               ▼                  │                 │
  │  ┌──────────────────────────┐    │                 │
  │  │   LogVisionTransformer   │    │                 │
  │  │  (ViT Anomaly Scoring)   │    │                 │
  │  └────────────┬─────────────┘    │                 │
  │               ▼                  │                 │
  │  ┌──────────────────────────┐    │                 │
  │  │     AnomalyDetector      │    │                 │
  │  │  (ViT + IsoForest + Z)   │    │                 │
  │  └────────────┬─────────────┘    │                 │
  └───────────────┼──────────────────┘                 │
                  │                                    │
                  ▼                                    ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │                        AGENT LAYER                               │
  │                                                                  │
  │  ┌─────────────────┐    ┌──────────────────┐                    │
  │  │  AnalystAgent   │    │   MitreMatcher   │◄───────────────────┘
  │  │  (GPT-4/Claude) │    │  (LLM + Vector)  │
  │  └────────┬────────┘    └────────┬─────────┘
  │           │                      │
  │           ▼                      ▼
  │  ┌──────────────────────────────────────┐
  │  │         ThreatOrchestrator           │
  │  │    (State Machine + Escalation)      │
  │  └──────────────────┬───────────────────┘
  │                     │
  │                     ▼
  │  ┌──────────────────────────────────────┐
  │  │        RLMitigationAgent             │
  │  │    (PPO: block/isolate/escalate)     │
  │  └──────────────────┬───────────────────┘
  └─────────────────────┼────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
  ┌──────────────┐ ┌──────────┐ ┌──────────────────┐
  │  MITIGATION  │ │  GRAPH   │ │   SIMULATION     │
  │   LAYER      │ │  LAYER   │ │   LAYER          │
  │              │ │          │ │                  │
  │ ResponseEng  │ │ Neo4j    │ │ ThreatSimulator  │
  │ Actions      │ │ Attack   │ │ Scenarios        │
  │              │ │ Graph    │ │                  │
  └──────────────┘ └──────────┘ └──────────────────┘
          │             │
          └──────┬──────┘
                 ▼
  ┌──────────────────────────────────┐
  │           API LAYER              │
  │   FastAPI + WebSocket Alerts     │
  │   REST endpoints + Dashboards    │
  └──────────────────────────────────┘
```

---

## Components

| Component | Description |
|-----------|-------------|
| **Ingestion** | Pulls logs from Elasticsearch, captures packets via Scapy/PyShark, normalizes to common schema, buffers via Redis |
| **Detection** | Converts log sequences to heatmap images, runs Vision Transformer for anomaly scoring, combines with Isolation Forest |
| **Agents** | LLM-powered analyst (GPT-4/Claude), MITRE ATT&CK matcher, RL-based mitigation decision agent |
| **Graph** | Neo4j attack graph tracking lateral movement, blast radius, kill chain stages |
| **Mitigation** | Automated response actions (block IP, isolate host, kill process) with policy enforcement |
| **Simulation** | Synthetic threat scenario generator for RL training and system testing |
| **API** | FastAPI REST + WebSocket interface for dashboards and SOC integration |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- NVIDIA GPU (optional, for ViT acceleration)

### 1. Clone and configure

```bash
git clone https://github.com/your-org/sentinel-ai.git
cd sentinel-ai
cp .env.example .env
# Edit .env with your API keys and configuration
```

### 2. Start infrastructure

```bash
docker-compose up -d elasticsearch kibana neo4j redis
# Wait for services to be healthy (~60 seconds)
docker-compose ps
```

### 3. Install Python dependencies

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Run Sentinel AI

```bash
# Start the API server
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Or run with Docker Compose (full stack)
docker-compose up -d
```

### 5. Access interfaces

| Service | URL |
|---------|-----|
| Sentinel API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Kibana | http://localhost:5601 |
| Neo4j Browser | http://localhost:7474 |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key for GPT-4 | required |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | optional |
| `ELASTICSEARCH_URL` | Elasticsearch connection URL | `http://localhost:9200` |
| `NEO4J_URI` | Neo4j bolt URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | required |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `SIMULATION_MODE` | Run in simulation mode | `false` |
| `ANOMALY_THRESHOLD` | Score threshold for alerts | `0.7` |
| `RL_MODEL_PATH` | Path to trained RL model | `models/rl_agent.zip` |

---

## API Reference

### REST Endpoints

```
GET  /health                          System health check
GET  /threats/active                  List active threats
GET  /threats/{id}                    Get threat details
POST /threats/{id}/mitigate           Trigger mitigation
GET  /graph/attack-path/{host}        Get attack graph for host
GET  /metrics                         System metrics
POST /simulation/start                Start threat simulation
WS   /ws/alerts                       Real-time alert stream
```

### Example: Trigger Mitigation

```bash
curl -X POST http://localhost:8000/threats/threat-001/mitigate \
  -H "Content-Type: application/json" \
  -d '{"action": "block_ip", "dry_run": false}'
```

---

## Training the RL Agent

```bash
python -m agents.rl_agent --train --timesteps 100000
```

---

## Running Simulations

```bash
# Start a specific attack scenario
curl -X POST http://localhost:8000/simulation/start \
  -H "Content-Type: application/json" \
  -d '{"scenario": "apt_lateral_movement", "intensity": 0.7}'
```

---

## Architecture Decisions

- **Vision Transformer for logs**: Log sequences encoded as 2D heatmaps allow spatial pattern recognition across time and feature dimensions, catching subtle multi-dimensional anomalies that 1D methods miss.
- **Multi-agent LLM pipeline**: Separating analyst reasoning from MITRE matching allows specialized prompting and independent confidence scoring.
- **RL for mitigation**: PPO learns optimal response policies from simulated environments, balancing false positive costs against threat neutralization rewards.
- **Neo4j for attack graphs**: Graph databases naturally model lateral movement and blast radius calculations that are expensive in relational DBs.

---

## License

MIT License — see LICENSE file for details.
