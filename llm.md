# SIH 26145 - Agent Progress Tracker

This document is intended for AI agents to understand the current state of the project, what has been completed, and what is up next according to the `sih26_plan.pdf`.

## Milestone 1: Passive Ingestion & Event Normalization (✅ Completed)
- **Environment:** Initialized Python 3 virtual environment (`setup.sh`) and installed dependencies (Pydantic, Redis, Tailer, Pytest).
- **Infrastructure:** Docker Compose stack created (`docker-compose.yml`) containing Redis (port 6379) and Zeek.
- **Zeek Configuration:** Wrote `zeek_scripts/local.zeek` to output JSON-formatted logs.
- **Schemas:** Created `src/ingestion/schemas.py` using Pydantic. It normalizes `conn`, `dns`, and `ssl` Zeek logs into a shared `NormalizedEvent` contract used by all downstream tracks.
- **Log Ingestion:** Implemented `src/ingestion/log_tailer.py` and `src/ingestion/redis_client.py`. The tailer asynchronously reads the Zeek JSON logs, validates them, and pushes them to the `events:live` Redis Stream. It also updates rolling host state (byte volume, unique destinations, etc.) via atomic pipelines.
- **Dry-run Validated:** Tested ingestion with a CTU-13 dataset sample and successfully streamed 88,000+ events into Redis.

## Milestone 2: Baselines & Core Detectors (✅ Completed)
- **Host-adaptive Baseline:** Implemented `BaselineEngine` in `src/detection/baseline.py`. Uses Redis rolling lists and HyperLogLogs (via buckets) to compute Median Absolute Deviation (MAD) for outbound bytes, connection counts, and DNS request rates.
- **Alert Schema:** Created the uniform `DetectionResult` Pydantic model (`src/detection/schemas.py`) so all detectors output a standard contract.
- **Baseline Detectors:** 
  - `ReconDetector`: Fast fan-out tracking using Redis Sets.
  - `C2BeaconingDetector`: SciPy periodogram and Coefficient of Variation for regular/jittered beacons.
  - `DGADetector`: Mock ML inference built around Shannon entropy and query length. (Training pipeline deferred).
  - `DNSTunnelDetector`: Tracks high query rates to single domains and suspicious `TXT`/`NULL` types.
  - `DDoSDetector` & `ExfiltrationDetector`: Z-score equivalent checks against the MAD baselines.
  - `EncryptedAnomalyDetector`: Evaluates traffic concentration against `ja4` fingerprints (schema updated, Zeek custom Dockerfile created to install `ja4` via `zkg`).
- **Detection Engine:** Implemented `src/detection/engine.py` to stream events from Redis `events:live`, run them through all detectors, and push hits to `alerts:live`.

## Milestone 3: Attack-chain Correlation & Incident Risk (🚧 Pending)
- **Correlation Engine:** Build a NetworkX graph linking alerts by shared IP, time overlap, and protocol. Group into incidents.
- **Incident Risk Scoring:** Calculate a composite risk score based on multi-stage chain structure rather than single isolated alerts.

## Repository Notes
- Always use the `.venv` for Python execution.
- Zeek logs are generated in `logs/` and pcaps are stored in `pcaps/` (both ignored by git).
- The `sih26-zeek` docker container is now custom-built (`zeek_scripts/Dockerfile`) to include the JA4 zkg package.

