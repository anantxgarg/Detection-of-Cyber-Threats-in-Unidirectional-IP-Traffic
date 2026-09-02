from __future__ import annotations

import hashlib

import redis

from app.correlation.features import compute_pair_features
from app.correlation.weighting import calculate_edge_weight
from app.main import parse_alert, process_alerts
from app.schemas.alert import Alert
from app.schemas.incident import Incident


class AlertStreamListener:
    """
    Reads alerts from Redis and maintains stable incident state.

    Incidents can evolve across batches when newly arriving alerts
    correlate with alerts already belonging to an existing incident.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        temporal_window: float = 300.0,
        correlation_threshold: float = 0.5,
        generate_llm_narrative: bool = False,
        start_from_beginning: bool = False,
    ) -> None:
        self.redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            decode_responses=True,
        )

        self.stream_name = "alerts:live"

        self.last_id = (
            "0-0"
            if start_from_beginning
            else "$"
        )

        self.temporal_window = temporal_window
        self.correlation_threshold = correlation_threshold

        self.generate_llm_narrative = (
            generate_llm_narrative
        )

        self.recent_alerts: list[Alert] = []

        self.incidents: dict[str, Incident] = {}

    def read_alerts(self, count: int = 100) -> list[str]:
        """Read alerts from the Redis alerts stream."""

        response = self.redis.xread(
            {self.stream_name: self.last_id},
            count=count,
            block=1000,
        )

        if not response:
            return []

        alerts: list[str] = []

        for _, messages in response:
            for message_id, fields in messages:
                self.last_id = message_id

                raw_alert = fields.get("alert")

                if raw_alert is not None:
                    alerts.append(raw_alert)

        return alerts

    @staticmethod
    def _alert_identity(alert: Alert) -> str:
        """Create a deterministic identity for an alert."""

        identity = (
            f"{alert.timestamp}|"
            f"{alert.src_ip}|"
            f"{alert.dst_ip}|"
            f"{alert.flow_id}|"
            f"{alert.threat_class.value}"
        )

        return hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _incident_identity(
        alerts: list[Alert],
    ) -> str:
        """Create a deterministic identity for an incident."""

        alert_ids = sorted(
            AlertStreamListener._alert_identity(alert)
            for alert in alerts
        )

        identity = "|".join(alert_ids)

        return hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()[:16]

    def _alert_correlates_with_incident(
        self,
        alert: Alert,
        incident: Incident,
    ) -> bool:
        """
        Determine whether a new alert is sufficiently correlated
        with an existing incident.

        Uses the same temporal window, correlation features, and
        weighted edge calculation as the correlation engine.
        """

        for existing_alert in incident.alerts:
            features = compute_pair_features(
                existing_alert,
                alert,
                temporal_window=self.temporal_window,
            )

            if features.time_delta > self.temporal_window:
                continue

            weight = calculate_edge_weight(features)

            if weight >= self.correlation_threshold:
                return True

        return False

    def _find_matching_incidents(
        self,
        new_incident: Incident,
    ) -> list[str]:
        """
        Find existing incidents that correlate with the new
        incident's alerts.
        """

        matching_ids: list[str] = []

        for incident_id, existing_incident in (
            self.incidents.items()
        ):
            for alert in new_incident.alerts:
                if self._alert_correlates_with_incident(
                    alert,
                    existing_incident,
                ):
                    matching_ids.append(incident_id)
                    break

        return matching_ids

    def _merge_incidents(
        self,
        new_incidents: list[Incident],
    ) -> list[Incident]:
        """
        Merge newly correlated incidents into stable incident state.

        A new incident can extend an existing incident even when its
        alerts are new, provided those alerts satisfy the correlation
        threshold against the existing incident.
        """

        updated_incidents: list[Incident] = []

        for new_incident in new_incidents:
            matching_ids = self._find_matching_incidents(
                new_incident
            )

            if not matching_ids:
                # Completely new incident.
                incident_id = self._incident_identity(
                    new_incident.alerts
                )

                new_incident.incident_id = incident_id

                self.incidents[incident_id] = new_incident

                updated_incidents.append(new_incident)

                continue

            # Use the first matching incident as the primary
            # incident to preserve its stable ID.
            primary_id = matching_ids[0]

            primary_incident = self.incidents[
                primary_id
            ]

            existing_alert_ids = {
                self._alert_identity(alert)
                for alert in primary_incident.alerts
            }

            # Add genuinely new alerts.
            for alert in new_incident.alerts:
                alert_id = self._alert_identity(alert)

                if alert_id not in existing_alert_ids:
                    primary_incident.alerts.append(alert)

            # If the new incident bridges two previously separate
            # incidents, merge those incidents as well.
            for other_id in matching_ids[1:]:
                other_incident = self.incidents.pop(
                    other_id
                )

                for alert in other_incident.alerts:
                    alert_id = self._alert_identity(alert)

                    if alert_id not in existing_alert_ids:
                        primary_incident.alerts.append(
                            alert
                        )
                        existing_alert_ids.add(
                            alert_id
                        )

            primary_incident.alerts.sort(
                key=lambda alert: alert.timestamp
            )

            # Recalculate all incident-level fields.
            refreshed = process_alerts(
                [
                    alert.model_dump_json()
                    for alert in primary_incident.alerts
                ],
                generate_llm_narrative=False,
            )

            if refreshed:
                refreshed_incident = refreshed[0]

                # Preserve the stable incident ID.
                refreshed_incident.incident_id = (
                    primary_id
                )

                # Preserve an existing LLM narrative.
                refreshed_incident.narrative = (
                    primary_incident.narrative
                )

                self.incidents[primary_id] = (
                    refreshed_incident
                )

                updated_incidents.append(
                    refreshed_incident
                )

        return updated_incidents

    def process_batch(
        self,
        count: int = 100,
    ) -> list[Incident]:
        """Process one batch of Redis alerts."""

        raw_alerts = self.read_alerts(
            count=count
        )

        if not raw_alerts:
            return []

        new_alerts = [
            parse_alert(raw_alert)
            for raw_alert in raw_alerts
        ]

        self.recent_alerts.extend(
            new_alerts
        )

        latest_timestamp = max(
            alert.timestamp
            for alert in self.recent_alerts
        )

        self.recent_alerts = [
            alert
            for alert in self.recent_alerts
            if (
                latest_timestamp - alert.timestamp
                <= self.temporal_window
            )
        ]

        new_incidents = process_alerts(
            [
                alert.model_dump_json()
                for alert in self.recent_alerts
            ],
            generate_llm_narrative=False,
        )

        return self._merge_incidents(
            new_incidents
        )

    def get_incidents(self) -> list[Incident]:
        """Return all currently stored incidents."""

        return list(
            self.incidents.values()
        )