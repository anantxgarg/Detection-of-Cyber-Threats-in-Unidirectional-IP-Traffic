"""
FastAPI application for the Sentinel AI dashboard.

Exposes:
  GET  /api/incidents    – correlated incident records
  GET  /api/stats        – live traffic metrics snapshot
  WS   /api/ws           – real-time push of incidents + telemetry ticks

The static frontend is served from the ``frontend/`` directory.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
import asyncio
import json
from datetime import datetime

from app.redis_listener import AlertStreamListener
from app.telemetry import TelemetryManager, normalize_threat_type, TICK_INTERVAL

app = FastAPI()
listener = AlertStreamListener(start_from_beginning=True)
telemetry = TelemetryManager()
active_connections: list[WebSocket] = []


# ---------------------------------------------------------------------------
# Threat taxonomy helpers
# ---------------------------------------------------------------------------

_THREAT_COLORS: dict[str, str] = {
    "DDoS / Volumetric":    "#EF4444",
    "Botnet C2":            "#F59E0B",
    "Port Scan / Recon":    "#3B82F6",
    "Data Exfiltration":    "#22D3EE",
    "DGA / DNS Tunnel":     "#8B5CF6",
    "Encrypted Anomaly":    "#EC4899",
}

_THREAT_ICONS: dict[str, str] = {
    "DDoS / Volumetric":    "⚡",
    "Botnet C2":            "♟",
    "Port Scan / Recon":    "⌁",
    "Data Exfiltration":    "⇧",
    "DGA / DNS Tunnel":     "◎",
    "Encrypted Anomaly":    "◈",
}


# ---------------------------------------------------------------------------
# Incident mapper
# ---------------------------------------------------------------------------

def map_incident_to_frontend(incident):
    alerts = incident.alerts
    first_alert = alerts[0] if alerts else None

    time_str = (
        datetime.fromtimestamp(first_alert.timestamp).strftime("%H:%M:%S")
        if first_alert
        else ""
    )
    src = first_alert.src_ip if first_alert else "Unknown"
    dst = first_alert.dst_ip if first_alert else "Unknown"

    mapped_evidence: dict[str, str] = {}

    for alert in alerts:
        det_ev = alert.evidence.get("detector_evidence", {})
        if isinstance(det_ev, dict):
            for k, v in det_ev.items():
                # Skip nested dicts/lists for cleanliness
                if not isinstance(v, (dict, list)):
                    label = k.replace("_", " ").title()
                    mapped_evidence[label] = (
                        str(round(v, 4)) if isinstance(v, float) else str(v)
                    )
        # Fallback: pull top-level evidence keys if detector_evidence is absent
        if not det_ev:
            for k, v in alert.evidence.items():
                if not isinstance(v, (dict, list)):
                    label = k.replace("_", " ").title()
                    mapped_evidence[label] = (
                        str(round(v, 4)) if isinstance(v, float) else str(v)
                    )

    # Deduplicate: also include SHAP top feature if available
    for alert in alerts:
        shap = alert.evidence.get("detector_evidence", {}).get("shap", [])
        if shap:
            top = shap[0]
            feat = top.get("feature", "").replace("_", " ").title()
            mapped_evidence["Top SHAP Feature"] = (
                f"{feat} ({top.get('direction', '')})"
            )
            break

    techniques = [t.get("technique_name", "") for t in incident.attack_techniques]
    desc = ", ".join(techniques) if techniques else "Suspicious behavior"

    # Normalise threat types to UI-friendly labels
    raw_types = incident.threat_types or []
    ui_types = list(dict.fromkeys(normalize_threat_type(t) for t in raw_types))
    ui_type_str = ", ".join(ui_types) if ui_types else "Unknown"

    return {
        "id": f"INC-{incident.incident_id[:6].upper()}",
        "time": time_str,
        "type": ui_type_str,
        "description": desc,
        "source": src,
        "destination": dst,
        "confidence": int(incident.risk * 100),
        "status": "Detected",
        "evidence": mapped_evidence,
        "reason": incident.narrative or "Multiple alerts correlated by the engine.",
    }


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(run_engine())
    asyncio.create_task(run_telemetry())


async def run_engine():
    """Continuously process alert batches and broadcast incident updates."""
    print("Correlation and risk engine started in background.")
    while True:
        try:
            incidents = await asyncio.to_thread(listener.process_batch)
            for incident in incidents:
                print(
                    f"Incident detected | "
                    f"id={incident.incident_id} | "
                    f"risk={incident.risk} | "
                    f"alerts={len(incident.alerts)} | "
                    f"threats={incident.threat_types}"
                )

            if incidents:
                mapped = [map_incident_to_frontend(i) for i in incidents]
                message = json.dumps(
                    {"type": "incident_update", "incidents": mapped}
                )
                await _broadcast(message)

        except Exception as exc:
            print(f"Error while processing alerts: {exc}")
            await asyncio.sleep(2)


async def run_telemetry():
    """Run a telemetry tick every TICK_INTERVAL seconds and broadcast."""
    print(f"Telemetry collector started (interval={TICK_INTERVAL}s).")
    while True:
        try:
            stats = await asyncio.to_thread(telemetry.tick)

            # Attach live threat distribution derived from current incidents
            incidents = listener.get_incidents()
            stats["threat_distribution"] = telemetry.compute_threat_distribution(
                incidents
            )

            message = json.dumps({"type": "telemetry_tick", "stats": stats})
            await _broadcast(message)

        except Exception as exc:
            print(f"Telemetry error: {exc}")

        await asyncio.sleep(TICK_INTERVAL)


async def _broadcast(message: str) -> None:
    """Send a message to all connected WebSocket clients."""
    for connection in active_connections.copy():
        try:
            await connection.send_text(message)
        except Exception:
            if connection in active_connections:
                active_connections.remove(connection)


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@app.get("/api/incidents")
def get_incidents():
    """Return all currently correlated incidents."""
    incidents = listener.get_incidents()
    return [map_incident_to_frontend(i) for i in incidents]


@app.get("/api/stats")
def get_stats():
    """
    Return the latest live traffic metrics snapshot.

    Shape::

        {
            "mbps": 12.3,
            "inbound": 7.6,
            "outbound": 4.7,
            "pps": 840.0,
            "fps": 22.4,
            "active_flows": 412,
            "unique_src": 38,
            "unique_dst": 15,
            "idle": false,
            "history": [{"time": "13:01:00", "mbps": 11.2, ...}, ...],
            "threat_distribution": [{"label": "Botnet C2", "count": 3, "pct": 60}, ...]
        }
    """
    stats = telemetry.get_stats()
    incidents = listener.get_incidents()
    stats["threat_distribution"] = telemetry.compute_threat_distribution(incidents)
    return stats


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    # Push current state immediately on connect
    try:
        stats = telemetry.get_stats()
        incidents = listener.get_incidents()
        stats["threat_distribution"] = telemetry.compute_threat_distribution(incidents)
        await websocket.send_text(
            json.dumps({"type": "telemetry_tick", "stats": stats})
        )
        mapped = [map_incident_to_frontend(i) for i in incidents]
        if mapped:
            await websocket.send_text(
                json.dumps({"type": "incident_update", "incidents": mapped})
            )
    except Exception:
        pass

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
