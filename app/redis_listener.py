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

        # Alerts kept inside the active correlation window.
        self.recent_alerts: list[Alert] = []

        # Stable incident store.
        self.incidents: dict[str, Incident] = {}

    def read_alerts(self, count: int = 100) -> list[str]:
        """Read new alerts from the Redis alerts stream."""

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
                # Advance Redis stream cursor.
                self.last_id = message_id

                raw_alert = fields.get("alert")

                if raw_alert is not None:
                    alerts.append(raw_alert)

        return alerts

    @staticmethod
    def _alert_identity(alert: Alert) -> str:
        """
        Create a deterministic identity for an alert.

        The identity allows duplicate alerts to be detected even
        when Redis delivers the same logical alert again.
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
        Determine whether an alert is sufficiently correlated
        with an existing incident.

        Uses the same temporal window, correlation features,
        and weighted edge calculation as the correlation engine.
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

        Returns only incidents that are:
        - newly created,
        - extended with a genuinely new alert, or
        - changed because multiple incidents were merged.
        """

        updated_incidents: list[Incident] = []

        for new_incident in new_incidents:

            matching_ids = self._find_matching_incidents(
                new_incident
            )

            # -------------------------------------------------------
            # CASE 1:
            # Completely new incident.
            # -------------------------------------------------------
            if not matching_ids:
                incident_id = self._incident_identity(
                    new_incident.alerts
                )

                new_incident.incident_id = incident_id

                self.incidents[incident_id] = new_incident

                updated_incidents.append(new_incident)

                continue

            # -------------------------------------------------------
            # CASE 2:
            # Existing incident found.
            #
            # Preserve the existing incident ID.
            # -------------------------------------------------------
            primary_id = matching_ids[0]

            primary_incident = self.incidents[
                primary_id
            ]

            existing_alert_ids = {
                self._alert_identity(alert)
                for alert in primary_incident.alerts
            }

            # Track whether anything actually changed.
            added_new_alert = False

            # -------------------------------------------------------
            # Add only genuinely new alerts.
            # -------------------------------------------------------
            for alert in new_incident.alerts:
                alert_id = self._alert_identity(alert)

                if alert_id not in existing_alert_ids:
                    primary_incident.alerts.append(alert)
                    existing_alert_ids.add(alert_id)
                    added_new_alert = True

            # -------------------------------------------------------
            # CASE 3:
            # Exact same incident was reconstructed.
            #
            # Nothing changed, so do not broadcast it again.
            # -------------------------------------------------------
            if (
                not added_new_alert
                and len(matching_ids) == 1
            ):
                continue

            # -------------------------------------------------------
            # CASE 4:
            # New incident bridges two or more existing incidents.
            # Merge them into the primary incident.
            # -------------------------------------------------------
            merged_other_incident = False

            for other_id in matching_ids[1:]:
                other_incident = self.incidents.pop(
                    other_id
                )

                merged_other_incident = True

                for alert in other_incident.alerts:
                    alert_id = self._alert_identity(alert)

                    if alert_id not in existing_alert_ids:
                        primary_incident.alerts.append(
                            alert
                        )

                        existing_alert_ids.add(
                            alert_id
                        )

            # -------------------------------------------------------
            # Sort alerts chronologically.
            # -------------------------------------------------------
            primary_incident.alerts.sort(
                key=lambda alert: alert.timestamp
            )

            # -------------------------------------------------------
            # Recalculate incident-level risk, evidence,
            # ATT&CK mappings, threat types, etc.
            # -------------------------------------------------------
            refreshed = process_alerts(
                [
                    alert.model_dump_json()
                    for alert in primary_incident.alerts
                ],
                generate_llm_narrative=False,
            )

            if refreshed:
                refreshed_incident = refreshed[0]

                # Preserve stable incident ID.
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

                # Broadcast because something actually changed.
                if (
                    added_new_alert
                    or merged_other_incident
                ):
                    updated_incidents.append(
                        refreshed_incident
                    )

        return updated_incidents

    def process_batch(
        self,
        count: int = 100,
    ) -> list[Incident]:
        """
        Process one batch of newly received Redis alerts.

        New alerts are added to the active temporal window.
        Only the active window is used for correlation.
        """

        raw_alerts = self.read_alerts(
            count=count
        )

        if not raw_alerts:
            return []

        # Parse only alerts that were actually received
        # from Redis during this batch.
        new_alerts = [
            parse_alert(raw_alert)
            for raw_alert in raw_alerts
        ]

        # Add them to the active correlation window.
        self.recent_alerts.extend(
            new_alerts
        )

        # -----------------------------------------------------------
        # Remove alerts older than the correlation window.
        # -----------------------------------------------------------
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

        # -----------------------------------------------------------
        # Build correlation incidents from the current active
        # temporal window.
        # -----------------------------------------------------------
        new_incidents = process_alerts(
            [
                alert.model_dump_json()
                for alert in self.recent_alerts
            ],
            generate_llm_narrative=False,
        )

        # Merge those results into stable incident state.
        return self._merge_incidents(
            new_incidents
        )

    def get_incidents(self) -> list[Incident]:
        """Return all currently stored incidents."""

        return list(
            self.incidents.values()
        )