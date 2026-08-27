# cyber-threat-detection
AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## Prerequisites
- **Docker** and **Docker Compose**
- **Python 3.10+**
- **Git**

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

## Running Unit Tests
To run the automated test suite:
```bash
source .venv/bin/activate
PYTHONPATH=. pytest tests/
```
