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

## Tech Stack

| Category | Technology |
|---|---|
| Backend API | FastAPI, Uvicorn |
| Real-time alerts | WebSockets |
| Agent reasoning | LangChain (OpenAI + Anthropic), GPT-4 / Claude |
| Deep learning | PyTorch |
| Vision Transformer | Vision Transformer (ViT) + Torch/Torchvision |
| ML anomaly detection | scikit-learn (e.g., Isolation Forest) |
| RL mitigation | Gymnasium, Stable-Baselines3 (PPO) |
| Log ingestion | Elasticsearch |
| Network capture | Scapy / PyShark |
| Event queue / pub-sub | Redis |
| Attack graph analytics | Neo4j |
| Orchestration / distribution | Docker, Docker Compose |

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

## CLI Commands

Run Sentinel AI using `python main.py` with the following commands:

### API Server (Default)

```bash
python main.py api
```

Starts the FastAPI server on `http://0.0.0.0:8000` with real-time threat detection, alert streaming, and REST endpoints.

### Train RL Agent

```bash
python main.py train --timesteps 100000
```

Train the reinforcement learning mitigation agent using PPO. Options:

```bash
python main.py train --timesteps 200000 --save-path ./models/agent.pkl
```

- `--timesteps`: Number of training timesteps (default: 100,000)
- `--save-path`: Directory to save trained model (optional)

### Run Threat Simulation

```bash
python main.py simulate --scenario brute_force_ssh --intensity 0.8
```

Generate synthetic threat scenarios for testing and RL training.

**Available scenarios:**
- `apt_lateral_movement` — Advanced persistent threat with lateral movement
- `brute_force_ssh` — SSH password attack simulation (default)
- `data_exfiltration` — Data theft scenario
- `ransomware` — Ransomware deployment
- `insider_threat` — Internal threat behavior
- `port_scan_recon` — Network reconnaissance
- `web_exploit` — Web application attack

**Options:**
```bash
python main.py simulate \
  --scenario ransomware \
  --intensity 0.5 \
  --duration 300
```

- `--scenario`: Attack scenario (default: `brute_force_ssh`)
- `--intensity`: Threat intensity 0.0-1.0 (default: 0.5)
- `--duration`: Simulation duration in seconds (optional)

### Detection Pipeline Only

```bash
python main.py detect
```

Run the anomaly detection pipeline without the API server. Processes logs from Elasticsearch and outputs alerts to console.

### Global Options

```bash
python main.py --log-level DEBUG api
```

- `--log-level`: Override logging verbosity (DEBUG, INFO, WARNING, ERROR)

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

## Architecture Decisions

- **Vision Transformer for logs**: Log sequences encoded as 2D heatmaps allow spatial pattern recognition across time and feature dimensions, catching subtle multi-dimensional anomalies that 1D methods miss.
- **Multi-agent LLM pipeline**: Separating analyst reasoning from MITRE matching allows specialized prompting and independent confidence scoring.
- **RL for mitigation**: PPO learns optimal response policies from simulated environments, balancing false positive costs against threat neutralization rewards.
- **Neo4j for attack graphs**: Graph databases naturally model lateral movement and blast radius calculations that are expensive in relational DBs.

---

## License

MIT License — see LICENSE file for details.
