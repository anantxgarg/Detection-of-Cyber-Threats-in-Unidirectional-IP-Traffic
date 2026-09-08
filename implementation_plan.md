# Live Dashboard & Frontend Hardcoded Variables Overhaul

## 1. Analysis Findings: Hardcoded Variables & Fake Graphs

A thorough inspection of `frontend/index.html` and `frontend/script.js` reveals extensive hardcoded values, mock calculations, and disconnected graphs:

### A. Network Traffic & Graphs
- **Hardcoded Initial Points**: `frontend/script.js` initializes `trafficData` with 31 hardcoded numbers (`[510, 525, 540, ..., 842]`) and `timeLabels` with 31 static strings (`["17:28", "17:29", ..., "17:58"]`).
- **Simulated Random Walk**: `updateTrafficData()` runs on a 5-second `setInterval` using `Math.random()` to jitter the line:
  ```javascript
  let variation = (Math.random() - 0.45) * 35;
  let next = previous + variation;
  ```
- **Derived Fake Metrics**: Every single bandwidth-related value on both the Overview and Traffic pages is derived from this fake random number:
  - Inbound Mbps: `Math.round(value * 0.613)`
  - Outbound Mbps: `Math.round(value - inbound)`
  - Packets/sec (`ppsValue`): `(value * 100).toFixed(1) + "K"`
  - Flows/sec (`fpsValue`): `(value * 3.1).toFixed(1) + "K"`
- **Static Chart Controls**: The `1H`, `6H`, `24H` time selector buttons have no event handlers and do not change the time range.
- **Static Status**: "Traffic flowing normally" is static text with a hardcoded green dot.

### B. Summary Cards & Counters
- **Active Flows**: The Dashboard summary card shows `18.6K` hardcoded in HTML (`#flowValue`), with a hardcoded trend `↑ 8.2%`. It is never updated in JavaScript.
- **Unique Host Counters**:
  - `sourceValue`: Hardcoded `1,284` in HTML.
  - `destinationValue`: Hardcoded `742` in HTML.
- **Navigation & Badge Counters**:
  - `sidebarThreatCount`: Hardcoded `7` in HTML (`<span class="nav-count" id="sidebarThreatCount">7</span>`).
  - `notificationBadge`: Hardcoded `3` in HTML (`<span class="notification-badge" id="notificationBadge">3</span>`).
- **Threat Detection Page Mini-Stats**:
  - Unique sources: Hardcoded `14`.
  - Average confidence: Hardcoded `94.8%`.
  - Detection latency: Hardcoded `1.8 sec`.

### C. Threat Distribution Breakdown
- The entire Threat Distribution widget on the Dashboard (lines 466–586 in `index.html`) is **100% static HTML**:
  - DDoS: Hardcoded `42%` (width `42%`)
  - Botnet C2: Hardcoded `24%` (width `24%`)
  - Port Scan: Hardcoded `18%` (width `18%`)
  - Exfiltration: Hardcoded `9%` (width `9%`)
  - DGA / DNS Tunnel: Hardcoded `7%` (width `7%`)
- There is **no JavaScript updating this breakdown**, meaning even when live alerts or incidents arrive, the distribution bars remain fixed at these fake numbers.

### D. Threat Taxonomy Mismatch
- Detectors emit real threat classes from `src/detection/schemas.py`:
  - `Recon/Scanning`
  - `C2 Beaconing`
  - `DGA`
  - `DNS Tunnelling`
  - `SYN-flood-like traffic anomaly`
  - `Potential Data Exfiltration / Abnormal Outbound Transfer`
  - `Encrypted-Session Behavioral Anomaly Detection`
- But `script.js` expects exact strings like `"DDoS"`, `"Botnet C2"`, `"Port Scan"`, `"Exfiltration"`, `"DGA / DNS Tunnel"`, `"Encrypted Malware"`.
- When real incidents arrive:
  - `getThreatColor` and `getThreatIcon` fall back to generic grey color and `!` icon.
  - The threat filter dropdown options do not match the real names, so filtering fails.

### E. Backend Gaps (`app/api.py`)
- The backend currently only consumes `alerts:live` via `AlertStreamListener` and exposes:
  - `GET /api/incidents`
  - `WebSocket /api/ws` (only broadcasting newly detected/updated incidents).
- The backend does **not** expose:
  - An endpoint for traffic throughput, flow counts, packet counts, or unique source/dest IPs from Redis `events:live`.
  - Live traffic time-series telemetry to feed the canvas charts.
  - An aggregate threat distribution endpoint.

---

## 2. Proposed Architecture & Solution

```mermaid
flowchart TD
    subgraph Storage [Redis Streams & Keys]
        E[events:live\nconn, dns, ssl]
        A[alerts:live\ndetector alerts]
    end

    subgraph Backend [FastAPI Server - app/api.py & app/telemetry.py]
        L[AlertStreamListener] -->|Correlates alerts| INC[Incidents Cache]
        TC[TelemetryCollector] -->|Aggregates live rates & IPs| METRICS[Live Metrics & History]
        WS[WebSocket Endpoint /api/ws]
        INC --> WS
        METRICS --> WS
        API_INC[/api/incidents]
        API_STATS[/api/stats]
    end

    subgraph Frontend [Web SOC Dashboard]
        WSC[WebSocket Client] --> UI_DISPATCH[Live Event Dispatcher]
        UI_DISPATCH --> CHARTS[Canvas Charts\nReal time-series]
        UI_DISPATCH --> BARS[Threat Distribution\nDynamic percentage bars]
        UI_DISPATCH --> CARDS[Live Metric Cards\nMbps, Flows, PPS, Unique IPs]
        UI_DISPATCH --> TABLES[Incidents & Evidence\nNormalized tags & filters]
    end

    E --> TC
    A --> L
```

### Key Components

1. **Telemetry Collector (`app/telemetry.py`)**:
   - Taps Redis `events:live` and `alerts:live`.
   - Computes:
     - Real rolling bandwidth (Mbps inbound, outbound, total).
     - Packets per second (pps) and Flows per second (fps).
     - Active flow count and unique source & destination IP sets.
     - Maintains a rolling 30-sample time-series buffer of real traffic throughput.
     - Computes real-time threat distribution breakdown across all detected incidents.

2. **Expanded API & WebSocket Protocol (`app/api.py`)**:
   - `GET /api/stats`: Returns current bandwidth, active flows, PPS, FPS, unique sources/dests, threat breakdown, and time-series history.
   - `WebSocket /api/ws`: Broadcasts structured message events:
     - `{"type": "incident_update", "incidents": [...]}`
     - `{"type": "telemetry_tick", "stats": {...}}` (broadcast every 2–3 seconds).

3. **Frontend Modernization (`frontend/script.js` & `frontend/index.html`)**:
   - Remove fake random-walk intervals and hardcoded arrays.
   - Dynamically render the **Threat Distribution widget** with live percentage calculations and correct color coding for all 7 MITRE/detector threat classes.
   - Bind all counters: `#trafficValue`, `#flowValue`, `#threatValue`, `#ppsValue`, `#fpsValue`, `#sourceValue`, `#destinationValue`, `#sidebarThreatCount`, `#notificationBadge`.
   - Normalize threat labels so names from the detector engine map cleanly to user-friendly titles, icons, and filter choices.
   - Add click handling to `1H`, `6H`, `24H` chart buttons to toggle rolling view scale.

---

## User Review Required

> [!IMPORTANT]
> The backend will compute traffic metrics directly from Redis `events:live` (which contains thousands of live Zeek flow and DNS events). When the log tailer or CTU-13 runner is streaming, the dashboard will reflect the real packet rates and byte throughput. If Redis has no events yet, it will gracefully display idle baseline telemetry (0 Mbps / 0 active flows) with clear indicators rather than fake random numbers.

> [!TIP]
> Threat taxonomy will be normalized:
> - `SYN-flood-like traffic anomaly` → **DDoS / Volumetric**
> - `C2 Beaconing` → **Botnet C2**
> - `Recon/Scanning` → **Port Scan / Recon**
> - `Potential Data Exfiltration / Abnormal Outbound Transfer` → **Data Exfiltration**
> - `DGA` / `DNS Tunnelling` → **DGA / DNS Tunnel**
> - `Encrypted-Session Behavioral Anomaly Detection` → **Encrypted Anomaly**

---

## Proposed Changes

### Backend

#### [NEW] [telemetry.py](file:///c:/VS%20Code/correlation-risk-engine/app/telemetry.py)
- Create a lightweight async telemetry aggregator `TelemetryManager`:
  - Reads rolling events from Redis `events:live`.
  - Computes byte rates, packet rates, active connection counts, unique IP sets.
  - Maintains a sliding window of historical points `[{ "time": "HH:MM:SS", "mbps": X, "inbound": Y, "outbound": Z }]`.
  - Calculates live threat distribution percentages based on active incidents.

#### [MODIFY] [api.py](file:///c:/VS%20Code/correlation-risk-engine/app/api.py)
- Integrate `TelemetryManager`.
- Add endpoint `@app.get("/api/stats")`.
- Enhance `@app.websocket("/api/ws")` to send telemetry ticks as well as incident updates.
- Enhance `map_incident_to_frontend` to handle multiple threat types and normalize threat class names for the UI.

---

### Frontend

#### [MODIFY] [index.html](file:///c:/VS%20Code/correlation-risk-engine/frontend/index.html)
- Replace static threat distribution bar items with a dynamic container `<div id="threatDistributionList" class="threat-bars"></div>`.
- Add proper IDs to mini-stat elements on the Threats Page:
  - `#uniqueSourcesCount`
  - `#avgConfidenceValue`
  - `#detectionLatencyValue`
- Update the threat filter dropdown options to align with all detector threat types.
- Ensure all metric spans have proper IDs for dynamic binding.

#### [MODIFY] [script.js](file:///c:/VS%20Code/correlation-risk-engine/frontend/script.js)
- Remove `trafficData` hardcoded array and `Math.random()` simulation.
- Implement `renderThreatDistribution(threats)` to dynamically generate and animate the progress bars based on live incident data.
- Implement `updateTelemetry(stats)` to update:
  - Dashboard bandwidth, flows, confidence, and trends.
  - Line charts `#trafficChart` and `#largeTrafficChart` with real time-series data.
  - PPS, FPS, Inbound/Outbound, Unique Sources, Unique Destinations.
  - Sidebar threat badge and notification badge.
- Enhance WebSocket listener to handle both `telemetry_tick` and `incident_update` messages.
- Implement time range selector for chart (1H / 6H / 24H).

---

## Verification Plan

### Automated Tests
- Run existing test suite to ensure no regressions:
  ```bash
  & ".\.venv\Scripts\python.exe" -m pytest tests/ -v
  ```
- Add unit tests for `app/telemetry.py` and new `/api/stats` endpoint:
  ```bash
  & ".\.venv\Scripts\python.exe" -m pytest tests/test_telemetry.py -v
  ```

### Manual Verification
1. Start the API server:
   ```bash
   & ".\.venv\Scripts\python.exe" -m app.runner
   ```
2. Verify endpoints:
   - `http://localhost:8081/api/incidents` returns correlated incident records.
   - `http://localhost:8081/api/stats` returns live traffic metrics and real history.
3. Open `http://localhost:8081` in browser:
   - Log in with `admin` / `admin123`.
   - Verify that all summary numbers (`trafficValue`, `flowValue`, `threatValue`, `sourceValue`, `destinationValue`, `ppsValue`, `fpsValue`) reflect live data.
   - Verify the Threat Distribution bars update dynamically to match the live detected threats.
   - Verify the Traffic Chart smoothly plots real timestamps and Mbps values.
4. Stream CTU-13 data or trigger alerts:
   ```bash
   & ".\.venv\Scripts\python.exe" scripts/run_ctu13_tests.py --max-events 1000 --stream
   ```
   - Verify the dashboard updates live via WebSocket without page refresh.
