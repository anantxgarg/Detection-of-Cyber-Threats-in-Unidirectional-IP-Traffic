# Architecture Overview

## System Architecture

The cyber-threat-detection system is a multi-stage pipeline for real-time threat detection from network traffic:

1. **Log Ingestion** → Zeek logs are tailed and normalized
2. **Detection Engine** → 7 specialized detectors analyze events
3. **Alert Correlation** → Related alerts are grouped into incidents
4. **Risk Scoring** → Incidents receive severity ratings
5. **Web Dashboard** → Live visualization and incident management

## Repository Structure

```
cyber-threat-detection/
├── app/                    # API server and correlation engine
│   ├── api.py             # FastAPI routes and WebSocket
│   ├── correlation/       # Alert correlation logic
│   ├── enrichment/        # ATT&CK mapping
│   ├── evidence/          # Evidence aggregation
│   ├── narrative/         # LLM incident narration
│   ├── risk/              # Risk scoring
│   └── telemetry.py       # Live metrics collection
├── frontend/              # Web dashboard (HTML/CSS/JS)
├── models/                # Trained ML models
│   ├── dga/              # DGA detection models
│   └── dns_tunnel/       # DNS tunnel detection models
├── research/              # Training scripts and prototypes
│   ├── dga/              # DGA research artifacts
│   └── dns_tunnel/       # DNS tunnel research artifacts
├── src/                   # Core detection pipeline
│   ├── detection/        # Detection engine and detectors
│   └── ingestion/        # Log parsing and normalization
├── tests/                 # Test suite (72 tests)
├── scripts/               # Demo and utility scripts
├── docs/                  # Documentation
└── zeek_scripts/          # Zeek configuration
```

## Component Details

### 1. Ingestion Layer (`src/ingestion/`)
- **log_tailer.py**: Tails Zeek JSON logs and publishes to Redis
- **schemas.py**: Pydantic schemas for Zeek log types (conn, dns, ssl)
- **Output**: Redis stream `events:live`

### 2. Detection Engine (`src/detection/`)
- **engine.py**: Main detection coordinator
- **baseline.py**: Host-adaptive baseline learning
- **detectors/**: 7 specialized threat detectors
  - `recon.py`: Port scanning and reconnaissance
  - `c2_beaconing.py`: Command & control beaconing patterns
  - `dga.py`: Domain Generation Algorithm detection (ML)
  - `dns_tunnel.py`: DNS tunneling detection (ML)
  - `ddos.py`: Distributed Denial of Service
  - `exfiltration.py`: Data exfiltration patterns
  - `encrypted_anomaly.py`: Suspicious encrypted traffic
- **Output**: Redis stream `alerts:live`

### 3. Correlation Layer (`app/`)
- **redis_listener.py**: Consumes alerts and correlates into incidents
- **correlation/engine.py**: Graph-based alert correlation
- **enrichment/attack_mapper.py**: MITRE ATT&CK technique mapping
- **risk/scorer.py**: Multi-factor risk calculation
- **Output**: Incident objects in Redis

### 4. API Layer (`app/api.py`)
- REST endpoints for incidents, stats, search
- WebSocket for live alert streaming
- Serves static frontend from `frontend/`

### 5. Frontend (`frontend/`)
- Single-page dashboard
- Live incident updates via WebSocket
- Traffic metrics visualization

## Data Flow

```
Zeek Logs → log_tailer → Redis events:live
           ↓
    Detection Engine (7 detectors)
           ↓
        Redis alerts:live
           ↓
    Correlation Engine
           ↓
    Incidents (Redis)
           ↓
    API Server ← WebSocket → Dashboard
```

## Machine Learning Models

### DGA Detection
- **Model**: XGBoost classifier
- **Features**: Character n-grams + handcrafted features (entropy, length, ratios)
- **Location**: `models/dga/`
- **Training**: See `research/dga/train_model.py`

### DNS Tunnel Detection
- **Model**: XGBoost classifier
- **Features**: Query length, entropy, subdomain count, byte ratios
- **Location**: `models/dns_tunnel/`
- **Training**: See `research/dns_tunnel/train_dns_model.py`

## Technology Stack

- **Language**: Python 3.10+
- **Frameworks**: FastAPI, Uvicorn
- **ML**: scikit-learn, XGBoost, SHAP
- **Data**: Redis (streams, caching)
- **Monitoring**: Zeek network analyzer
- **Frontend**: Vanilla JavaScript, HTML5, CSS3

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment instructions.

## Testing

72 tests covering:
- Unit tests for each detector
- Integration tests with CTU-13 dataset
- Correlation engine tests
- Risk scoring tests
- API endpoint tests

Run: `pytest tests/ -v`
