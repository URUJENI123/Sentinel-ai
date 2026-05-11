# Sentinel AI — Explained Like You're 12

---

## What Is This Thing?

Imagine your school has a security guard. But instead of one tired human walking the halls, you have a **super-smart robot** that:

- Watches **every door, window, and hallway** at the same time
- Recognizes when something looks weird
- Calls in backup experts to figure out what's happening
- Decides on its own whether to lock a door, call the police, or just keep watching
- Gets **smarter every day** by practicing on fake break-in scenarios

That's Sentinel AI — but for **computer networks** instead of school hallways.

It watches your company's computers 24/7, spots hackers, figures out what they're doing, and fights back — all automatically.

---

## The Big Picture (How It All Fits Together)

```
INTERNET / HACKERS
        │
        ▼
┌───────────────────────────────────────────────────────┐
│  STEP 1 — INGESTION: "Collect everything happening"   │
│  Reads logs + watches network traffic                 │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  STEP 2 — DETECTION: "Does this look weird?"          │
│  Turns logs into pictures, uses AI to spot anomalies  │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  STEP 3 — AGENTS: "What exactly is happening?"        │
│  AI analyst reads the alert, matches it to known      │
│  hacker playbooks (MITRE ATT&CK)                      │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  STEP 4 — DECISION: "What should we do?"              │
│  A robot that learned from millions of practice       │
│  scenarios picks the best response                    │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  STEP 5 — ACTION: "Do it!"                            │
│  Block the hacker's IP, isolate the infected          │
│  computer, or call a human expert                     │
└───────────────────┬───────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────┐
│  STEP 6 — GRAPH: "Draw the map of the attack"         │
│  Tracks which computers the hacker touched and        │
│  how they moved around                                │
└───────────────────────────────────────────────────────┘
```

---

## Each Part Explained

---

### 📥 Part 1 — Ingestion (`ingestion/`)

**What it does:** Collects all the "clues" happening on the network.

Think of it like a detective who reads every sticky note, listens to every phone call, and watches every door in the building at the same time.

**Two collectors:**

| Collector | What it watches | File |
|-----------|----------------|------|
| `LogIngester` | System logs — login attempts, errors, warnings from every computer | `log_ingester.py` |
| `PacketIngester` | Actual network traffic — who's sending data to who, how much, on what port | `packet_ingester.py` |

**The pipeline (`pipeline.py`)** runs both collectors at the same time and dumps everything into a **Redis queue** — think of Redis like a conveyor belt. Events go in one end, and the detector picks them up from the other end.

```
LogIngester ──┐
              ├──► Redis Queue (conveyor belt) ──► Detector
PacketIngester┘
```

---

### 🔍 Part 2 — Detection (`detection/`)

**What it does:** Looks at all those clues and asks "does this look normal?"

This is the most clever part. It uses **three different methods** and combines them:

---

#### Method 1: Turn Logs Into a Picture 🖼️ (`log_heatmap.py`)

This sounds weird but it's genius. Instead of reading logs as text, the system converts them into a **colored image** (like a heatmap).

- The **X-axis** (left to right) = time
- The **Y-axis** (top to bottom) = different types of events (logins, network traffic, file changes, etc.)
- The **color brightness** = how intense/frequent that activity is

So a normal day looks like a calm, mostly dark image. A hacker brute-forcing passwords looks like a **bright red stripe** on the login row.

```
Normal day:          Brute force attack:
░░░░░░░░░░░░         ░░░░░░░░████████
░░░░░░░░░░░░         ░░░░░░░░░░░░░░░░
░░░░░░░░░░░░         ░░░░░░░░░░░░░░░░
```

---

#### Method 2: Vision Transformer (ViT) 👁️ (`vision_transformer.py`)

This is an AI model originally designed to look at photos. Here it looks at those log heatmap images and asks: "Does this image look like an attack?"

It was trained on thousands of examples of normal vs. attack patterns. It gives back an **anomaly score** from 0.0 (totally normal) to 1.0 (definitely an attack).

It can spot 5 types of anomalies:
- `NORMAL` — everything's fine
- `BRUTE_FORCE` — someone's hammering passwords
- `LATERAL_MOVEMENT` — a hacker moving between computers
- `DATA_EXFILTRATION` — someone stealing data
- `MALWARE` — malicious software running

---

#### Method 3: Isolation Forest + Z-Score 📊 (`anomaly_detector.py`)

Two classic math-based methods that work alongside the AI:

- **Isolation Forest**: Learns what "normal" looks like for each computer/IP address. If something behaves very differently from its own history, it gets flagged.
- **Z-Score**: Measures how far a reading is from the average. Like if a computer normally sends 1MB of data per hour and suddenly sends 500MB — that's a huge z-score.

---

#### Combining All Three

The final **composite score** is a weighted average:

```
Composite Score = (ViT score × 50%) + (Isolation Forest × 30%) + (Z-Score × 20%)
```

If the score is high enough, an **AnomalyAlert** is created with a severity level:

| Score | Severity |
|-------|----------|
| 0.40+ | LOW |
| 0.65+ | MEDIUM |
| 0.80+ | HIGH |
| 0.92+ | CRITICAL |

---

### 🤖 Part 3 — Agents (`agents/`)

Once an alert is created, three AI agents work together to understand it.

---

#### Agent 1: The Analyst (`analyst_agent.py`)

This is **GPT-4** (the same AI behind ChatGPT) acting as a senior cybersecurity expert with 15 years of experience.

It reads the alert and the raw logs and answers questions like:
- What type of attack is this? (brute force? ransomware? insider threat?)
- How confident are we? (0–100%)
- Which computers are affected?
- What stage of the attack are we at?
- What should we do?
- What are the indicators of compromise (IOCs)?

It returns a structured **ThreatAssessment** report.

---

#### Agent 2: The MITRE Matcher (`mitre_matcher.py`)

MITRE ATT&CK is a **giant encyclopedia of hacker techniques** — a real-world database maintained by security researchers. It has hundreds of techniques like:

- `T1110` — Brute Force
- `T1078` — Valid Accounts (using stolen passwords)
- `T1041` — Exfiltration Over C2 Channel
- `T1486` — Data Encrypted for Impact (ransomware)

This agent takes the analyst's report and matches it to specific techniques in that encyclopedia. It also builds an **attack chain** — the sequence of steps the hacker took.

The MITRE data lives in `config/mitre_attack.json`.

---

#### Agent 3: The RL Decision Maker (`rl_agent.py`)

This is a **Reinforcement Learning** agent — think of it like a robot that learned to play a video game.

The "game" is: given a threat, pick the best response. The robot practiced millions of times in a simulated environment and learned:

- If anomaly score is 0.92+ → escalate to a human (too dangerous to handle alone)
- If score is 0.80+ → isolate the infected computer from the network
- If score is 0.65+ → block the attacker's IP address
- If score is 0.40+ → just send an alert
- If score is low → do nothing (probably a false alarm)

It uses an algorithm called **PPO (Proximal Policy Optimization)** — one of the best RL algorithms available.

The 6 possible actions it can take:

| Action | What it means |
|--------|--------------|
| `do_nothing` | False alarm, ignore it |
| `alert_only` | Send a notification to the security team |
| `block_ip` | Add the attacker's IP to the firewall blocklist |
| `isolate_system` | Cut the infected computer off from the network |
| `kill_process` | Terminate the malicious program running on a computer |
| `escalate_to_human` | Page the on-call security analyst immediately |

---

#### The Orchestrator (`orchestrator.py`)

This is the **boss** that coordinates all three agents. It runs the full pipeline for every alert:

```
Alert received
    │
    ├─► AnalystAgent (GPT-4 analysis)
    │
    ├─► MitreMatcher (match to ATT&CK techniques)
    │
    ├─► AttackGraph (update the map of the attack)
    │
    ├─► RLAgent (decide what to do)
    │
    └─► ResponseEngine (actually do it)
```

It also tracks the **state** of every threat:

```
DETECTED → ANALYSING → MITRE_MATCHED → MITIGATING → CONTAINED
                                                   → ESCALATED
                                                   → CLOSED
```

---

### 🗺️ Part 4 — Attack Graph (`graph/`)

**What it does:** Draws a map of the attack in a graph database (Neo4j).

Imagine a web of connected dots:
- Each **dot** is a computer, user, or MITRE technique
- Each **line** is a connection (network link, login, lateral movement)

When a hacker moves from Computer A to Computer B to Computer C, the graph records that path. This lets you:

- See the **full attack path** from entry point to target
- Calculate the **blast radius** — how many computers could be affected
- Find all **compromised hosts** at a glance

Neo4j is a special database designed for this kind of connected data. It's much better at "find all paths between these two nodes" than a regular database.

---

### 🛡️ Part 5 — Mitigation (`mitigation/`)

**What it does:** Actually executes the response actions.

The `ResponseEngine` has two modes:

- **Dry-run mode** (default, safe): Logs what it *would* do without actually doing it. Great for testing.
- **Live mode**: Actually calls the firewall API, EDR (Endpoint Detection & Response) API, or PagerDuty to take real action.

Actions it can execute:

```python
block_ip        → Calls firewall API: "DENY ALL FROM 203.0.113.10"
isolate_system  → Calls EDR API: "Cut 192.168.1.50 off from the network"
kill_process    → Calls EDR API: "Kill process mimikatz.exe on dc01"
escalate_to_human → Sends PagerDuty alert to wake up the on-call analyst
alert_only      → Posts to Slack/Teams webhook
```

Every action is logged with a full audit trail — who did what, when, and why.

---

### 🎮 Part 6 — Simulation (`simulation/`)

**What it does:** Generates fake attacks so the system can be tested and the RL agent can be trained.

It's like a **flight simulator for cybersecurity**. Instead of real hackers, it generates realistic fake attack events.

7 built-in attack scenarios:

| Scenario | What happens |
|----------|-------------|
| `apt_lateral_movement` | A sophisticated hacker group moves through the network step by step |
| `brute_force_ssh` | Thousands of password guesses until one works |
| `data_exfiltration` | Steal credentials, then copy gigabytes of data out |
| `ransomware` | Phishing email → disable antivirus → encrypt all files → ransom note |
| `insider_threat` | A trusted employee quietly steals data over weeks |
| `port_scan_recon` | Hacker maps out the network before attacking |
| `web_exploit` | SQL injection → upload a webshell → run commands on the server |

Each scenario generates realistic log events with real IP addresses, usernames, commands, and network traffic patterns.

---

### 🌐 Part 7 — API (`api/`)

**What it does:** Exposes everything through a web interface so dashboards and other tools can connect.

Built with **FastAPI** — a modern Python web framework. It has:

**REST endpoints** (normal web requests):

```
GET  /health                    → Is the system running?
GET  /threats/active            → Show me all current threats
GET  /threats/{id}              → Tell me about this specific threat
POST /threats/{id}/mitigate     → Take action on this threat
GET  /graph/attack-path/{host}  → Show the attack path from this computer
GET  /graph/blast-radius/{host} → How many computers could be affected?
GET  /metrics                   → System statistics
POST /simulation/start          → Start a fake attack scenario
```

**WebSocket** (real-time streaming):

```
WS /ws/alerts  → Stream live alerts to a dashboard as they happen
```

The API docs are auto-generated and available at `http://localhost:8000/docs`.

---

## The Full Flow — A Real Example

Let's trace what happens when a hacker tries to brute-force SSH into your server:

```
1. Hacker sends 500 failed SSH login attempts from 203.0.113.10

2. LogIngester reads these from Elasticsearch
   → 500 events: "Failed password for root from 203.0.113.10"

3. Pipeline pushes them to Redis queue

4. AnomalyDetector picks them up:
   → LogHeatmapGenerator: login row lights up bright red
   → ViT model: "This looks like BRUTE_FORCE, score=0.88"
   → Isolation Forest: "This IP has never done this before, score=0.91"
   → Z-Score: "500 failures in 2 minutes is 8 standard deviations above normal"
   → Composite score: 0.89 → Severity: HIGH
   → AnomalyAlert created!

5. Orchestrator receives the alert:
   → AnalystAgent (GPT-4): 
      "This is a brute force attack. Confidence: 92%. 
       Affected: webserver01. Stage: Initial Access.
       Recommended: Block IP immediately."
   
   → MitreMatcher:
      "Matches T1110 (Brute Force) with 95% confidence.
       Attack chain: [T1110 → T1078]"
   
   → AttackGraph: Adds alert node, links to 203.0.113.10 host node
   
   → RLAgent: 
      "Score=0.89, stage=delivery → action: block_ip (confidence: 0.87)"

6. ResponseEngine:
   → [DRY-RUN] Would add firewall rule: DENY ALL FROM 203.0.113.10
   → Logs the action with full audit trail

7. Threat state: DETECTED → ANALYSING → MITRE_MATCHED → MITIGATING → CONTAINED

8. Redis pub/sub: Broadcasts the alert to all connected dashboards

9. Dashboard shows: 🔴 HIGH THREAT — Brute Force SSH — 203.0.113.10 — CONTAINED
```

All of that happens in **under 5 seconds**, automatically, with no human needed.

---

## The Tech Stack (What Tools It Uses)

| Tool | What it is | Used for |
|------|-----------|---------|
| **Python** | Programming language | Everything |
| **FastAPI** | Web framework | The REST API |
| **GPT-4 / Claude** | Large Language Models | Analyst agent, MITRE matcher |
| **PyTorch** | Deep learning library | Vision Transformer model |
| **Stable Baselines3** | RL library | Training the PPO agent |
| **Elasticsearch** | Search/log database | Storing and querying logs |
| **Neo4j** | Graph database | Attack graph |
| **Redis** | In-memory cache/queue | Event queue, pub/sub alerts |
| **Docker** | Container platform | Running all services together |
| **LangChain** | LLM framework | Connecting GPT-4 to the pipeline |
| **scikit-learn** | ML library | Isolation Forest |
| **Loguru** | Logging library | Pretty, structured logs |

---

## The Files and Folders

```
sentinel-ai/
│
├── main.py                    ← Start here. Runs the whole system.
│
├── config/
│   ├── settings.py            ← All configuration (API keys, thresholds, etc.)
│   └── mitre_attack.json      ← The encyclopedia of hacker techniques
│
├── ingestion/
│   ├── log_ingester.py        ← Reads logs from Elasticsearch
│   ├── packet_ingester.py     ← Captures network packets
│   └── pipeline.py            ← Coordinates both, feeds Redis queue
│
├── detection/
│   ├── log_heatmap.py         ← Converts logs to heatmap images
│   ├── vision_transformer.py  ← AI model that reads the heatmap images
│   └── anomaly_detector.py    ← Combines ViT + IsoForest + Z-Score
│
├── agents/
│   ├── analyst_agent.py       ← GPT-4 powered threat analyst
│   ├── mitre_matcher.py       ← Matches threats to ATT&CK techniques
│   ├── rl_agent.py            ← Reinforcement learning decision maker
│   └── orchestrator.py        ← The boss that runs the whole pipeline
│
├── graph/
│   └── attack_graph.py        ← Neo4j attack map (lateral movement tracking)
│
├── mitigation/
│   └── response_engine.py     ← Executes block/isolate/escalate actions
│
├── simulation/
│   └── threat_simulator.py    ← Generates fake attacks for testing/training
│
├── api/
│   └── main.py                ← FastAPI web server (REST + WebSocket)
│
├── prompts/
│   ├── analyst_prompt.md      ← Instructions given to GPT-4 analyst
│   └── mitre_prompt.md        ← Instructions given to GPT-4 MITRE matcher
│
├── .env                       ← Your secret API keys (never share this!)
├── docker-compose.yml         ← Starts all services (ES, Neo4j, Redis, etc.)
└── requirements.txt           ← Python packages needed
```

---

## How to Run It

### The Easy Way (Docker)

```bash
# 1. Copy the example config and fill in your API keys
cp .env.example .env

# 2. Start all the background services
docker-compose up -d elasticsearch kibana neo4j redis

# 3. Install Python packages
pip install -r requirements.txt

# 4. Start Sentinel AI
python main.py api
```

Then open `http://localhost:8000/docs` to see the API.

### Other Commands

```bash
# Run a fake attack to test the system
python main.py simulate --scenario brute_force_ssh --intensity 0.8

# Train the RL agent (takes a while)
python main.py train --timesteps 100000

# Run just the detection pipeline (no API)
python main.py detect
```

---

## The Settings (`.env` file)

The `.env` file holds all the secret keys and configuration. The important ones:

| Setting | What it does |
|---------|-------------|
| `OPENAI_API_KEY` | Your OpenAI key so GPT-4 can analyze threats |
| `ANTHROPIC_API_KEY` | Backup AI (Claude) if GPT-4 is unavailable |
| `ELASTICSEARCH_URL` | Where your logs are stored |
| `NEO4J_PASSWORD` | Password for the attack graph database |
| `REDIS_URL` | Where the event queue lives |
| `ANOMALY_THRESHOLD` | How sensitive the detector is (0.7 = 70% sure before alerting) |
| `DRY_RUN` | `true` = safe mode (just logs actions), `false` = actually blocks IPs |
| `SIMULATION_MODE` | `true` = use fake data instead of real logs |

---

## The Reinforcement Learning Agent — Deeper Dive

The RL agent is trained like this:

1. **Environment**: A simulated world where threats appear randomly
2. **State**: 5 numbers describing the current situation:
   - How anomalous is the activity? (0–1)
   - What type of threat is it? (encoded as a number)
   - How many computers are affected? (0–1, normalized)
   - What stage of the attack? (0–1, encoded)
   - How long since we detected it? (0–1, normalized)
3. **Actions**: 6 choices (do nothing, alert, block, isolate, kill, escalate)
4. **Rewards**: Points for correct decisions, penalties for wrong ones:
   - Correct mitigation: **+10 points**
   - False positive (blocked innocent traffic): **-5 points**
   - Missed a real threat: **-20 points**
   - Did nothing when threat was present: **-1 point**

After 100,000+ practice rounds, the agent learns the optimal policy — when to be aggressive and when to hold back.

---

## Why Is This Cool?

Most security systems just **alert** humans and let them decide. Sentinel AI actually **acts**:

- It's faster than any human — responds in seconds, not hours
- It never gets tired, distracted, or goes on vacation
- It learns from every attack it sees
- It explains its reasoning (the analyst agent writes a full report)
- It maps the entire attack, not just the single event that triggered the alert
- It can be tested safely with simulated attacks before going live

---

## Summary in One Sentence

Sentinel AI watches your entire network, converts activity into pictures that an AI can understand, uses GPT-4 to figure out what's happening, and then a robot trained on millions of practice scenarios decides whether to block the attacker, isolate the infected computer, or wake up a human — all in under 5 seconds.
