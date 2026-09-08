"""
Tests for app/telemetry.py

Tests the TelemetryManager without a real Redis connection by
patching Redis internals.
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from app.telemetry import TelemetryManager, normalize_threat_type, THREAT_TAXONOMY


# ---------------------------------------------------------------------------
# normalize_threat_type
# ---------------------------------------------------------------------------

class TestNormalizeThreatType:

    def test_known_types_map_correctly(self):
        assert normalize_threat_type("C2 Beaconing") == "Botnet C2"
        assert normalize_threat_type("Recon/Scanning") == "Port Scan / Recon"
        assert normalize_threat_type("DGA") == "DGA / DNS Tunnel"
        assert normalize_threat_type("DNS Tunnelling") == "DGA / DNS Tunnel"
        assert normalize_threat_type(
            "SYN-flood-like traffic anomaly"
        ) == "DDoS / Volumetric"
        assert normalize_threat_type(
            "Potential Data Exfiltration / Abnormal Outbound Transfer"
        ) == "Data Exfiltration"
        assert normalize_threat_type(
            "Encrypted-Session Behavioral Anomaly Detection"
        ) == "Encrypted Anomaly"

    def test_unknown_type_passthrough(self):
        assert normalize_threat_type("Something unknown") == "Something unknown"

    def test_all_taxonomy_keys_covered(self):
        """Every raw key in THREAT_TAXONOMY must produce a non-empty label."""
        for raw, label in THREAT_TAXONOMY.items():
            assert label, f"Empty label for raw type: {raw!r}"
            assert normalize_threat_type(raw) == label


# ---------------------------------------------------------------------------
# TelemetryManager._idle_stats
# ---------------------------------------------------------------------------

class TestIdleStats:

    def test_idle_stats_shape(self):
        stats = TelemetryManager._idle_stats()
        assert stats["mbps"] == 0.0
        assert stats["inbound"] == 0.0
        assert stats["outbound"] == 0.0
        assert stats["pps"] == 0.0
        assert stats["fps"] == 0.0
        assert stats["active_flows"] == 0
        assert stats["unique_src"] == 0
        assert stats["unique_dst"] == 0
        assert stats["history"] == []
        assert stats["idle"] is True


# ---------------------------------------------------------------------------
# TelemetryManager.tick with mocked Redis
# ---------------------------------------------------------------------------

def make_manager_with_events(event_fields_list):
    """
    Build a TelemetryManager whose Redis is mocked to return a
    predefined list of event field dicts on the first xread call.
    """
    tm = TelemetryManager.__new__(TelemetryManager)

    mock_redis = MagicMock()
    # Simulate one xread response with the supplied events
    stream_messages = [
        (f"1-{i}", fields) for i, fields in enumerate(event_fields_list)
    ]
    mock_redis.xread.return_value = [("events:live", stream_messages)]

    tm._redis = mock_redis
    tm._stream_name = "events:live"
    tm._last_id = "$"
    tm._window_start = time.monotonic()
    tm._bytes_in = 0.0
    tm._bytes_out = 0.0
    tm._pkt_count = 0
    tm._flow_count = 0
    tm._src_ips = set()
    tm._dst_ips = set()
    tm._total_flows = 0
    from collections import deque
    tm._history = deque(maxlen=30)
    tm._last_stats = TelemetryManager._idle_stats()

    return tm


class TestTelemetryManagerTick:

    def _make_conn_event(self, src, dst, orig_bytes, resp_bytes, orig_pkts, resp_pkts):
        record = {
            "id.orig_h": src,
            "id.resp_h": dst,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
        }
        return {"event": json.dumps(record)}

    def test_tick_returns_stat_dict_with_required_keys(self):
        tm = make_manager_with_events([
            self._make_conn_event("1.1.1.1", "2.2.2.2", 1000, 500, 10, 5),
        ])
        stats = tm.tick()

        required_keys = [
            "mbps", "inbound", "outbound", "pps", "fps",
            "active_flows", "unique_src", "unique_dst", "history", "idle",
        ]
        for key in required_keys:
            assert key in stats, f"Missing key: {key}"

    def test_tick_with_no_events_produces_idle_stats(self):
        tm = make_manager_with_events([])
        # Make xread return nothing
        tm._redis.xread.return_value = []
        stats = tm.tick()

        assert stats["mbps"] == 0.0
        assert stats["idle"] is True
        assert stats["unique_src"] == 0

    def test_tick_counts_unique_ips(self):
        events = [
            self._make_conn_event("10.0.0.1", "8.8.8.8", 100, 50, 1, 1),
            self._make_conn_event("10.0.0.2", "8.8.8.8", 100, 50, 1, 1),
            self._make_conn_event("10.0.0.1", "1.1.1.1", 100, 50, 1, 1),  # duplicate src
        ]
        tm = make_manager_with_events(events)
        stats = tm.tick()

        assert stats["unique_src"] == 2   # 10.0.0.1 and 10.0.0.2
        assert stats["unique_dst"] == 2   # 8.8.8.8 and 1.1.1.1

    def test_tick_appends_history_entry(self):
        tm = make_manager_with_events([
            self._make_conn_event("1.1.1.1", "2.2.2.2", 1000, 500, 10, 5),
        ])
        assert len(tm._history) == 0
        tm.tick()
        assert len(tm._history) == 1
        entry = tm._history[0]
        assert "time" in entry
        assert "mbps" in entry

    def test_tick_accumulates_active_flow_count(self):
        events = [
            self._make_conn_event("1.1.1.1", "2.2.2.2", 100, 50, 1, 1),
            self._make_conn_event("3.3.3.3", "4.4.4.4", 100, 50, 1, 1),
        ]
        tm = make_manager_with_events(events)
        stats = tm.tick()
        assert stats["active_flows"] == 2


# ---------------------------------------------------------------------------
# TelemetryManager.compute_threat_distribution
# ---------------------------------------------------------------------------

class TestThreatDistribution:

    def _make_incident(self, threat_types):
        """Minimal incident-like object with threat_types attribute."""
        inc = MagicMock()
        inc.threat_types = threat_types
        return inc

    def test_single_type_is_100_percent(self):
        tm = TelemetryManager.__new__(TelemetryManager)
        incidents = [
            self._make_incident(["C2 Beaconing"]),
        ]
        dist = tm.compute_threat_distribution(incidents)
        assert len(dist) == 1
        assert dist[0]["label"] == "Botnet C2"
        assert dist[0]["pct"] == 100

    def test_two_types_equal_split(self):
        tm = TelemetryManager.__new__(TelemetryManager)
        incidents = [
            self._make_incident(["C2 Beaconing"]),
            self._make_incident(["Recon/Scanning"]),
        ]
        dist = tm.compute_threat_distribution(incidents)
        labels = {d["label"] for d in dist}
        assert "Botnet C2" in labels
        assert "Port Scan / Recon" in labels
        for d in dist:
            assert d["pct"] == 50

    def test_empty_incidents_returns_empty_list(self):
        tm = TelemetryManager.__new__(TelemetryManager)
        dist = tm.compute_threat_distribution([])
        assert dist == []

    def test_sorted_by_count_descending(self):
        tm = TelemetryManager.__new__(TelemetryManager)
        incidents = [
            self._make_incident(["C2 Beaconing"]),
            self._make_incident(["C2 Beaconing"]),
            self._make_incident(["DGA"]),
        ]
        dist = tm.compute_threat_distribution(incidents)
        assert dist[0]["label"] == "Botnet C2"
        assert dist[0]["count"] == 2


# ---------------------------------------------------------------------------
# FastAPI /api/stats endpoint smoke-test
# ---------------------------------------------------------------------------

class TestStatsEndpoint:

    def test_stats_endpoint_returns_200_with_correct_shape(self):
        """
        Test that /api/stats returns the expected shape.
        We patch out Redis and the listener so no real connections needed.
        """
        from fastapi.testclient import TestClient
        import app.api as api_module

        # Patch TelemetryManager.tick and get_stats to avoid Redis
        with patch.object(api_module.telemetry, "get_stats", return_value={
            "mbps": 5.0,
            "inbound": 3.0,
            "outbound": 2.0,
            "pps": 100.0,
            "fps": 10.0,
            "active_flows": 50,
            "unique_src": 5,
            "unique_dst": 3,
            "history": [],
            "idle": False,
        }), patch.object(
            api_module.listener, "get_incidents", return_value=[]
        ), patch.object(
            api_module.telemetry, "compute_threat_distribution", return_value=[]
        ):
            client = TestClient(api_module.app)
            response = client.get("/api/stats")

        assert response.status_code == 200
        data = response.json()

        assert "mbps" in data
        assert "inbound" in data
        assert "outbound" in data
        assert "pps" in data
        assert "fps" in data
        assert "active_flows" in data
        assert "unique_src" in data
        assert "unique_dst" in data
        assert "history" in data
        assert "threat_distribution" in data
