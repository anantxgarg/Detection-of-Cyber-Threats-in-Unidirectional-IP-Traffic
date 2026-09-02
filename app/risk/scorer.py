from __future__ import annotations

from app.schemas.alert import Alert


class RiskScorer:
    """
    Calculates an overall risk score for a correlated incident.

    Detector confidence remains the confidence produced by each
    individual detector. This class only aggregates those alerts
    into an incident-level risk score.
    """

    def __init__(
        self,
        confidence_weight: float = 0.6,
        diversity_weight: float = 0.4,
    ) -> None:
        self.confidence_weight = confidence_weight
        self.diversity_weight = diversity_weight

    def calculate_risk(self, alerts: list[Alert]) -> float:
        """
        Calculate incident-level risk from all correlated alerts.
        """

        if not alerts:
            return 0.0

        # Aggregate confidence across all alerts.
        #
        # We use the average confidence so that every alert
        # contributes to the incident score.
        average_confidence = sum(
            alert.confidence for alert in alerts
        ) / len(alerts)

        # Count distinct detector/threat types.
        threat_types = {
            alert.threat_class for alert in alerts
        }

        # Three or more distinct threat types represents
        # maximum detector diversity for this scoring model.
        diversity_score = min(
            len(threat_types) / 3.0,
            1.0,
        )

        risk = (
            self.confidence_weight * average_confidence
            + self.diversity_weight * diversity_score
        )

        return round(min(risk, 1.0), 4)