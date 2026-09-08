"""
Telemetry collector for the Sentinel AI dashboard.

Reads from Redis ``events:live`` to compute real-time network
throughput metrics:

  - Total / inbound / outbound bandwidth (Mbps)
  - Packets per second (PPS)
  - Flows per second (FPS)
  - Active flow count and unique source / destination IP sets
  - A rolling 30-sample time-series buffer for the traffic chart

Threat distribution is derived from the in-memory incident store
maintained by ``AlertStreamListener``.
"""

from __future__ import annotations

import json
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List

import redis


# ---------------------------------------------------------------------------
# Threat taxonomy normalisation
# ---------------------------------------------------------------------------

# Maps raw detector threat_class values → friendly UI label
THREAT_TAXONOMY: Dict[str, str] = {
    "SYN-flood-like traffic anomaly":                      "DDoS / Volumetric",
    "C2 Beaconing":                                        "Botnet C2",
    "Recon/Scanning":                                      "Port Scan / Recon",
    "Potential Data Exfiltration / Abnormal Outbound Transfer": "Data Exfiltration",
    "DGA":                                                 "DGA / DNS Tunnel",
    "DNS Tunnelling":                                      "DGA / DNS Tunnel",
    "Encrypted-Session Behavioral Anomaly Detection":      "Encrypted Anomaly",
}


def normalize_threat_type(raw: str) -> str:
    """Return the UI-friendly label for a detector threat class."""
    return THREAT_TAXONOMY.get(raw, raw)


# ---------------------------------------------------------------------------
# Rolling window helpers
# ---------------------------------------------------------------------------

# Number of historical points kept for the time-series chart
HISTORY_SIZE = 30

# How often (seconds) the background telemetry tick fires
TICK_INTERVAL = 3.0

# Rolling window (seconds) over which bytes/packets are accumulated
WINDOW_SECONDS = 5.0


class TelemetryManager:
    """
    Aggregates live network metrics from Redis ``events:live``.

    Usage::

        tm = TelemetryManager()
        await asyncio.to_thread(tm.tick)   # call periodically
        stats = tm.get_stats()
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
    ) -> None:
        self._redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            decode_responses=True,
        )

        self._stream_name = "events:live"
        self._last_id = "0-0"  # read events from the beginning of the stream

        # Rolling accumulation buckets
        self._window_start = time.monotonic()
        self._bytes_in: float = 0.0
        self._bytes_out: float = 0.0
        self._pkt_count: int = 0
        self._flow_count: int = 0
        self._src_ips: set[str] = set()
        self._dst_ips: set[str] = set()

        # Active flow counter (total seen since start, capped at 99 999)
        self._total_flows: int = 0

        # Historical time-series – each entry: {time, mbps, inbound, outbound}
        self._history: deque[Dict[str, Any]] = deque(maxlen=HISTORY_SIZE)

        # Last snapshot (returned to callers immediately)
        self._last_stats: Dict[str, Any] = self._idle_stats()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def tick(self) -> Dict[str, Any]:
        """
        Read new events from Redis, update running counters, and
        produce a fresh stats snapshot.  Call this in a background thread
        every ``TICK_INTERVAL`` seconds.
        """
        self._consume_events()
        stats = self._compute_snapshot()
        self._last_stats = stats
        return stats

    def get_stats(self) -> Dict[str, Any]:
        """Return the most recently computed stats snapshot."""
        return self._last_stats

    def compute_threat_distribution(
        self,
        incidents: list,
    ) -> List[Dict[str, Any]]:
        """
        Build a sorted threat distribution list from live incidents.

        Parameters
        ----------
        incidents:
            List of ``Incident`` objects from ``AlertStreamListener``.

        Returns
        -------
        List of dicts ordered by count descending::

            [{"label": "Botnet C2", "count": 4, "pct": 44}, ...]
        """
        counts: Dict[str, int] = {}

        for incident in incidents:
            for raw_type in (incident.threat_types or []):
                label = normalize_threat_type(raw_type)
                counts[label] = counts.get(label, 0) + 1

        total = sum(counts.values()) or 1

        distribution = [
            {
                "label": label,
                "count": count,
                "pct": round(count / total * 100),
            }
            for label, count in counts.items()
        ]

        distribution.sort(key=lambda x: x["count"], reverse=True)
        return distribution

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _consume_events(self) -> None:
        """Read up to 500 new events from Redis in one shot."""
        try:
            response = self._redis.xread(
                {self._stream_name: self._last_id},
                count=500,
                block=100,  # ms; short block so we don't hang the tick
            )
        except redis.RedisError:
            return

        if not response:
            return

        for _, messages in response:
            for message_id, fields in messages:
                self._last_id = message_id
                self._process_event(fields)

    def _process_event(self, fields: Dict[str, str]) -> None:
        """
        Parse one Zeek-style event record and accumulate counters.

        Expected JSON keys (subset used here):
          orig_bytes, resp_bytes, orig_pkts, resp_pkts,
          id.orig_h, id.resp_h, proto
        """
        raw = fields.get("event") or fields.get("data") or ""
        if not raw:
            # Some producers write fields directly
            record = fields
        else:
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                return

        orig_bytes = _safe_int(record, "orig_bytes") or _safe_int(record, "orig_ip_bytes") or 0
        resp_bytes = _safe_int(record, "resp_bytes") or _safe_int(record, "resp_ip_bytes") or 0
        orig_pkts = _safe_int(record, "orig_pkts") or 0
        resp_pkts = _safe_int(record, "resp_pkts") or 0

        self._bytes_in += resp_bytes
        self._bytes_out += orig_bytes
        self._pkt_count += orig_pkts + resp_pkts
        self._flow_count += 1
        self._total_flows += 1

        src = _safe_str(record, "id.orig_h") or _safe_str(record, "src_ip") or ""
        dst = _safe_str(record, "id.resp_h") or _safe_str(record, "dst_ip") or ""
        if src:
            self._src_ips.add(src)
        if dst:
            self._dst_ips.add(dst)

    def _compute_snapshot(self) -> Dict[str, Any]:
        """Compute per-second rates and build the stats dict."""
        now = time.monotonic()
        elapsed = max(now - self._window_start, 0.001)

        mbps_in = (self._bytes_in * 8) / (elapsed * 1_000_000)
        mbps_out = (self._bytes_out * 8) / (elapsed * 1_000_000)
        mbps_total = mbps_in + mbps_out

        pps = self._pkt_count / elapsed
        fps = self._flow_count / elapsed

        # Round to 2 dp max
        mbps_total = round(mbps_total, 2)
        mbps_in = round(mbps_in, 2)
        mbps_out = round(mbps_out, 2)
        pps = round(pps, 1)
        fps = round(fps, 1)

        unique_src = len(self._src_ips)
        unique_dst = len(self._dst_ips)
        active_flows = min(self._total_flows, 99_999)

        # Append to rolling history
        ts = datetime.now().strftime("%H:%M:%S")
        self._history.append(
            {
                "time": ts,
                "mbps": mbps_total,
                "inbound": mbps_in,
                "outbound": mbps_out,
            }
        )

        # Reset window counters
        self._bytes_in = 0.0
        self._bytes_out = 0.0
        self._pkt_count = 0
        self._flow_count = 0
        self._window_start = now

        return {
            "mbps": mbps_total,
            "inbound": mbps_in,
            "outbound": mbps_out,
            "pps": pps,
            "fps": fps,
            "active_flows": active_flows,
            "unique_src": unique_src,
            "unique_dst": unique_dst,
            "history": list(self._history),
            "idle": mbps_total == 0.0,
        }

    @staticmethod
    def _idle_stats() -> Dict[str, Any]:
        return {
            "mbps": 0.0,
            "inbound": 0.0,
            "outbound": 0.0,
            "pps": 0.0,
            "fps": 0.0,
            "active_flows": 0,
            "unique_src": 0,
            "unique_dst": 0,
            "history": [],
            "idle": True,
        }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _safe_int(record: Any, key: str) -> int:
    """Parse an integer field, returning 0 on failure."""
    try:
        val = record.get(key, 0) if isinstance(record, dict) else 0
        return int(val) if val else 0
    except (ValueError, TypeError):
        return 0


def _safe_str(record: Any, key: str) -> str:
    """Parse a string field, returning '' on failure."""
    try:
        return str(record.get(key, "")) if isinstance(record, dict) else ""
    except Exception:
        return ""
