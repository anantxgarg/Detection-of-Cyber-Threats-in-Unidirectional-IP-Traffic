# cyber-threat-detection
AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## Prerequisites
- **Docker** and **Docker Compose**
- **Python 3.10+**
- **Git**

## Repository Structure

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/STRUCTURE.md`](docs/STRUCTURE.md) for detailed repository layout and component descriptions.

Quick overview:
- `src/`: Core detection pipeline (ingestion + detection engine)
- `app/`: API server and correlation engine
- `frontend/`: Web dashboard
- `models/`: Trained ML models
- `research/`: Training scripts and prototypes
- `tests/`: Test suite

## Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd SIH26
   ```

2. **Initialize the Python Environment:**
   Run the provided setup script to create a virtual environment (`.venv`) and install dependencies:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
   
   Alternatively, use pip directly:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Start the Infrastructure (Redis & Zeek):**
   The pipeline relies on Redis for state management and event streaming, and Zeek for network log generation.
   ```bash
   docker compose up -d redis
   docker compose up -d zeek
   ```

## Running the Pipeline

The pipeline consists of two main Python services running concurrently. You will need to open two separate terminal windows for these.

**Terminal 1: Start the Log Ingestion Tailer**
This service tails the Zeek JSON logs and pushes normalized events to Redis streams.
```bash
source .venv/bin/activate
PYTHONPATH=. python -u -m src.ingestion.log_tailer
```

**Terminal 2: Start the Detection Engine**
This service consumes the Redis streams, updates host baselines, and runs the detection algorithms.
```bash
source .venv/bin/activate
PYTHONPATH=. python -u -m src.detection.engine
```

## Testing with PCAP Data

To test the system against a sample packet capture (e.g., the provided CTU-13 dataset):

1. **Clear old logs** (optional but recommended for a clean run):
   ```bash
   rm -f logs/*.log
   ```

2. **Run Zeek against the PCAP:**
   Execute Zeek inside its container to parse the PCAP file and generate JSON logs in the `logs/` directory.
   ```bash
   docker compose exec zeek zeek -C -r /pcaps/ctu13_sample.pcap /zeek_scripts/local.zeek
   ```

3. **Observe the Output:**
   Switch to Terminal 2 (Detection Engine). As Zeek generates the logs, the tailer will stream them, and you should see the detection engine outputting baseline updates and triggering alerts (e.g., `🔥 ALERT [C2 Beaconing] Confidence:...`).

## Running Tests Through the CTU-13 Dataset

You can run tests through the **CTU-13 Botnet dataset** (Neris botnet scenario, infected host `147.32.84.165`) in three convenient ways:

### 1. Automated Integration Tests (`pytest`)
Run the comprehensive CTU-13 automated test suite:
```bash
# Windows PowerShell
& ".\.venv\Scripts\python.exe" -m pytest tests/test_ctu13.py -v

# Linux / macOS
pytest tests/test_ctu13.py -v
```
To run the complete test suite (all 72 unit and integration tests):
```bash
pytest tests/
```

### 2. Standalone Presentation Demo Runner
For live presentations, demonstrations, or evaluation benchmarks, run the presentation script:
```bash
# Quick demo run (processes 2,000 CTU-13 events)
python scripts/run_ctu13_tests.py --max-events 2000

# Full presentation run streaming to live Redis / Web UI
python scripts/run_ctu13_tests.py --max-events 5000 --stream
```
This prints an executive incident report featuring:
- Ingestion metrics & schema normalization
- Threat detection counts (C2 Beaconing, DGA, DNS Tunnelling, Recon)
- Graph correlation into security incidents
- Multi-stage risk scores (escalated for multi-vector botnet attacks)
- MITRE ATT&CK technique mapping (T1071, T1568.002, T1046, T1071.004)
- Explainable AI (SHAP feature contributions)

### 3. Live Presentation with Web Dashboard
To demonstrate the full visual SOC dashboard during a presentation:
1. Ensure Redis is running: `docker compose up -d redis`
2. Start the API server:
   ```bash
   python -m app.runner
   ```
3. Open your browser to `http://localhost:8081` and log in with:
   - **Username:** `admin`
   - **Password:** `admin123`
4. In another terminal, stream the CTU-13 dataset:
   ```bash
   python scripts/run_ctu13_tests.py --max-events 3000 --stream
   ```
   Watch the live incidents, attack chains, risk meters, and MITRE matrix populate in real time!


## Research and Model Training

Model training scripts and standalone detector prototypes are in the `research/` directory.
These are not required for running the detection system.

See `research/README.md` for details on retraining models or analyzing detector logic.

## Repository Structure

- `src/`: Core detection pipeline (ingestion + detection engine)
- `app/`: API server and correlation engine
- `frontend/`: Web dashboard
- `models/`: Trained ML models
- `research/`: Training scripts and prototypes
- `tests/`: Test suite (72 tests)
- `docs/`: Documentation
