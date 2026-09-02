from __future__ import annotations

import hashlib

import redis

from app.main import parse_alert, process_alerts
from app.schemas.alert import Alert
from app.schemas.incident import Incident


class AlertStreamListener:
    """
    Reads alerts from Redis and maintains stable incident state.

    The same correlated incident keeps the same incident_id across
    successive batches. New related alerts are added to the existing
    incident instead of creating a new incident ID.

    LLM narrative generation is optional and never required for the
    detection/correlation/risk pipeline.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        temporal_window: float = 300.0,
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

        # By default, start in live mode and only process new alerts.
        #
        # For replay/testing, explicitly use:
        # start_from_beginning=True
        self.last_id = (
            "0-0"
            if start_from_beginning
            else "$"
        )

        self.temporal_window = temporal_window

        # LLM generation is optional.
        self.generate_llm_narrative = generate_llm_narrative

        # Alerts currently inside the rolling correlation window.
        self.recent_alerts: list[Alert] = []

        # Stable incident state.
        self.incidents: dict[str, Incident] = {}

    def read_alerts(self, count: int = 100) -> list[str]:
        """
        Read alerts from the Redis alerts stream.

        In live mode, the listener waits for new messages.
        """

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
        """
        Create a deterministic identity for an alert.

        This prevents the same alert from being added repeatedly
        to an incident.
        """

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
    def _incident_identity(alerts: list[Alert]) -> str:
        """
        Create a deterministic identity for an incident.

        The identity is based on the identities of the alerts
        belonging to the incident.
        """

        alert_ids = sorted(
            AlertStreamListener._alert_identity(alert)
            for alert in alerts
        )

        identity = "|".join(alert_ids)

        return hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()[:16]

    def _merge_incidents(
        self,
        new_incidents: list[Incident],
    ) -> list[Incident]:
        """
        Merge newly correlated incidents into stable incident state.

        If a newly correlated incident contains an alert that already
        belongs to a known incident, preserve the existing incident ID.

        Otherwise, create a new stable incident ID.
        """

        updated_incidents: list[Incident] = []

        for new_incident in new_incidents:
            new_alert_ids = {
                self._alert_identity(alert)
                for alert in new_incident.alerts
            }

            matching_incident_id: str | None = None

            # Look for an existing incident sharing an alert.
            for (
                incident_id,
                existing_incident,
            ) in self.incidents.items():

                existing_alert_ids = {
                    self._alert_identity(alert)
                    for alert in existing_incident.alerts
                }

                if new_alert_ids & existing_alert_ids:
                    matching_incident_id = incident_id
                    break

            if matching_incident_id is None:
                # New incident.
                incident_id = self._incident_identity(
                    new_incident.alerts
                )

                new_incident.incident_id = incident_id

                self.incidents[incident_id] = new_incident

                updated_incidents.append(new_incident)

                continue

            # Existing incident: add any new alerts.
            existing_incident = self.incidents[
                matching_incident_id
            ]

            existing_alert_ids = {
                self._alert_identity(alert)
                for alert in existing_incident.alerts
            }

            for alert in new_incident.alerts:
                alert_id = self._alert_identity(alert)

                if alert_id not in existing_alert_ids:
                    existing_incident.alerts.append(alert)

            # Keep alerts chronologically ordered.
            existing_incident.alerts.sort(
                key=lambda alert: alert.timestamp
            )

            # Re-run correlation/risk/evidence/ATT&CK using
            # the complete merged alert set.
            refreshed = process_alerts(
                [
                    alert.model_dump_json()
                    for alert in existing_incident.alerts
                ],
                generate_llm_narrative=False,
            )

            if refreshed:
                refreshed_incident = refreshed[0]

                # Preserve the stable incident ID.
                refreshed_incident.incident_id = (
                    matching_incident_id
                )

                # Preserve an existing LLM narrative.
                refreshed_incident.narrative = (
                    existing_incident.narrative
                )

                self.incidents[matching_incident_id] = (
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
        """
        Process one batch of Redis alerts.

        Normal live processing does NOT require the LLM.
        """

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

        # Determine the newest alert timestamp.
        latest_timestamp = max(
            alert.timestamp
            for alert in self.recent_alerts
        )

        # Keep only alerts inside the rolling
        # correlation window.
        self.recent_alerts = [
            alert
            for alert in self.recent_alerts
            if (
                latest_timestamp - alert.timestamp
                <= self.temporal_window
            )
        ]

        # Run the core pipeline without the LLM.
        new_incidents = process_alerts(
            [
                alert.model_dump_json()
                for alert in self.recent_alerts
            ],
            generate_llm_narrative=False,
        )

        # Merge newly discovered incidents into
        # the persistent incident state.
        return self._merge_incidents(
            new_incidents
        )

    def get_incidents(self) -> list[Incident]:
        """Return all currently stored incidents."""

        return list(
            self.incidents.values()
        )