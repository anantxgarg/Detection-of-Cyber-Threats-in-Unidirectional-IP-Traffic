# Repository Structure

## Overview
This document describes the final post-merge repository structure after cleanup and consolidation.

## Directory Layout

```
cyber-threat-detection/
├── app/                          # Backend API and correlation engine
│   ├── __init__.py
│   ├── api.py                    # FastAPI application (WebSocket + REST)
│   ├── main.py                   # Alert processing and incident creation
│   ├── redis_listener.py         # Alert stream consumer and correlator
│   ├── runner.py                 # API server entry point
│   ├── telemetry.py              # Live metrics aggregation
│   ├── correlation/              # Alert correlation logic
│   │   ├── engine.py            # Graph-based correlation engine
│   │   ├── features.py          # Alert pair feature extraction
│   │   └── weighting.py         # Edge weight calculation
│   ├── enrichment/               # Threat intelligence enrichment
│   │   └── attack_mapper.py     # MITRE ATT&CK technique mapping
│   ├── evidence/                 # Evidence aggregation
│   │   └── aggregator.py        # Evidence collection from alerts
│   ├── narrative/                # LLM-based incident narration
│   │   └── generator.py         # Ollama-based narrative generation
│   ├── risk/                     # Risk scoring
│   │   └── scorer.py            # Incident-level risk calculation
│   └── schemas/                  # Pydantic schemas
│       ├── alert.py             # Alert schema
│       └── incident.py          # Incident schema
│
├── frontend/                     # Web dashboard (served by FastAPI)
│   ├── index.html               # Main dashboard HTML
│   ├── script.js                # Dashboard JavaScript
│   └── style.css                # Dashboard CSS
│
├── models/                       # Trained ML models (tracked in git)
│   ├── README.md                # Model documentation
│   ├── dga/                     # DGA detection models
│   │   ├── combined_dga_model.pkl
│   │   └── ngram_vectorizer.pkl
│   └── dns_tunnel/              # DNS tunnel detection models
│       └── dns_tunnel_model.pkl
│
├── research/                     # Training scripts and prototypes (not in runtime path)
│   ├── README.md                # Research directory documentation
│   ├── dga/                     # DGA research artifacts
│   │   ├── train_model.py      # Model training pipeline
│   │   ├── standalone_detector.py
│   │   └── data/               # Training datasets
│   └── dns_tunnel/              # DNS tunnel research artifacts
│       ├── train_dns_model.py
│       ├── inspect_data.py
│       ├── standalone_detector.py
│       └── data/
│
├── src/                          # Core detection pipeline
│   ├── __init__.py
│   ├── detection/               # Detection engine and algorithms
│   │   ├── __init__.py
│   │   ├── baseline.py         # Host-adaptive baseline engine
│   │   ├── engine.py           # Main detection engine (Redis consumer)
│   │   ├── model_loader.py     # Centralized model loading utility
│   │   ├── schemas.py          # Detection result schemas
│   │   └── detectors/          # Individual threat detectors
│   │       ├── c2_beaconing.py
│   │       ├── ddos.py
│   │       ├── dga.py          # DGA detection (uses models/dga/)
│   │       ├── dns_tunnel.py   # DNS tunnel detection (uses models/dns_tunnel/)
│   │       ├── encrypted_anomaly.py
│   │       ├── exfiltration.py
│   │       └── recon.py
│   └── ingestion/               # Log ingestion and normalization
│       ├── __init__.py
│       ├── log_tailer.py       # Zeek log tailer (Redis producer)
│       ├── redis_client.py     # Redis stream publisher
│       └── schemas.py          # Zeek log schemas (conn, dns, ssl)
│
├── tests/                        # Test suite (90 tests)
│   ├── test_alert.py
│   ├── test_attack_mapper.py
│   ├── test_correlation.py
│   ├── test_ctu13.py           # CTU-13 integration tests
│   ├── test_detection.py
│   ├── test_ingestion.py
│   ├── test_main.py
│   ├── test_narrative.py
│   ├── test_redis_listener.py
│   ├── test_risk.py
│   └── test_telemetry.py
│
├── scripts/                      # Utility and demo scripts
│   ├── download_datasets.sh
│   ├── run_ctu13_tests.py      # CTU-13 demo runner
│   ├── run_narrative_demo.py
│   └── test_live_listener.py
│
├── docs/                         # Documentation
│   ├── ARCHITECTURE.md          # System architecture and components
│   ├── CONTRIBUTING.md          # Contribution guidelines
│   ├── SCHEMA.md                # Data schemas
│   ├── STRUCTURE.md            # This file
│   ├── TEAM_RULES.md
│   └── TERMINOLOGY.md
│
├── zeek_scripts/                 # Zeek network monitor configuration
│   ├── Dockerfile
│   └── local.zeek
│
├── docker-compose.yml            # Infrastructure (Redis + Zeek)
├── requirements.txt              # Python dependencies
├── setup.sh                      # Environment setup script
├── .gitignore
└── README.md                     # Main project documentation
```

## Production Runtime Components

### 1. Ingestion Pipeline
- **Entry point**: `src/ingestion/log_tailer.py`
- **Function**: Tails Zeek JSON logs, normalizes events, pushes to Redis `events:live`
- **Schemas**: `src/ingestion/schemas.py` (ConnRecord, DnsRecord, SslRecord)

### 2. Detection Engine
- **Entry point**: `src/detection/engine.py`
- **Function**: Consumes `events:live`, runs 7 detectors, emits to Redis `alerts:live`
- **Detectors**:
  1. Recon/Scanning (`recon.py`)
  2. C2 Beaconing (`c2_beaconing.py`)
  3. DGA (`dga.py`) - Uses ML models
  4. DNS Tunneling (`dns_tunnel.py`) - Uses ML models
  5. DDoS (`ddos.py`)
  6. Data Exfiltration (`exfiltration.py`)
  7. Encrypted Anomaly (`encrypted_anomaly.py`)

### 3. Correlation & API Layer
- **Entry point**: `app/runner.py`
- **Components**:
  - `api.py`: FastAPI server, WebSocket, REST endpoints
  - `redis_listener.py`: Alert correlation and incident management
  - `telemetry.py`: Live metrics aggregation
  - `correlation/`: Graph-based alert correlation
  - `enrichment/`: MITRE ATT&CK mapping
  - `risk/`: Risk scoring

### 4. Web Dashboard
- **Location**: `frontend/`
- **Served by**: FastAPI (`app/api.py` line 264)
- **Features**: Live incident view, traffic metrics, threat distribution

## ML Models

Models are in `models/` directory and loaded by detectors at runtime:
- **DGA Detection**: XGBoost classifier + n-gram vectorizer
- **DNS Tunnel Detection**: XGBoost classifier with behavioral features

Training scripts are in `research/` directory.

## Research vs Production

- **Production code**: `src/`, `app/`, `frontend/`
- **Research/training**: `research/`
- **Models**: `models/` (used by production, generated by research)

The `research/` directory contains:
- Model training pipelines
- Data analysis scripts
- Standalone detector prototypes
- Historical experimentation code

These are NOT imported by production code and are preserved for model retraining and documentation.

## Key Invariants

1. **Frontend**: Always served from `frontend/` directory by FastAPI
2. **Models**: Always loaded from `models/<detector>/` paths via `model_loader.py`
3. **Research**: Never imported by production code
4. **Dependencies**: Defined in `requirements.txt`, installed via `setup.sh`
5. **Tests**: Must pass before deployment (run via `pytest tests/`)

## Deployment Checklist

1. Install dependencies: `./setup.sh`
2. Start infrastructure: `docker compose up -d redis zeek`
3. Run tests: `pytest tests/ -v`
4. Start detection engine: `python -m src.detection.engine`
5. Start API server: `python -m app.runner`
6. Access dashboard: `http://localhost:8081`

## Development Guidelines

- **Adding detectors**: Create new file in `src/detection/detectors/`, register in `engine.py`
- **Adding models**: Place in `models/<name>/`, load via `model_loader.py`
- **Frontend changes**: Edit files in `frontend/` directory only
- **Research work**: Add to `research/` directory, keep separate from production
- **Tests**: Add to `tests/`, ensure all tests pass before merging
