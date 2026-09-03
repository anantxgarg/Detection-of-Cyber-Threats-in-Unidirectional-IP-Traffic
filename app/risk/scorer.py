from __future__ import annotations

from app.schemas.alert import Alert


class RiskScorer:
    """
    Calculates an incident-level risk score.

    Detector confidence remains the confidence produced by each
    individual detector. Risk is a separate incident-level measure
    that combines average detector confidence with detector diversity.
    """

    def __init__(
        self,
        confidence_weight: float = 0.6,
        diversity_weight: float = 0.4,
    ) -> None:
        if confidence_weight < 0 or diversity_weight < 0:
            raise ValueError("Risk weights must be non-negative.")

        if confidence_weight + diversity_weight <= 0:
            raise ValueError("At least one risk weight must be positive.")

        self.confidence_weight = confidence_weight
        self.diversity_weight = diversity_weight

    def calculate_risk(self, alerts: list[Alert]) -> float:
        """
        Calculate incident-level risk from correlated alerts.

        Risk combines:
        - average detector confidence
        - diversity of distinct detector/threat types

        The final score is bounded to [0, 1].
        """

        if not alerts:
            return 0.0

        average_confidence = sum(
            max(0.0, min(alert.confidence, 1.0))
            for alert in alerts
        ) / len(alerts)

        threat_types = {
            alert.threat_class
            for alert in alerts
        }

        diversity_score = min(
            len(threat_types) / 3.0,
            1.0,
        )

        weight_total = (
            self.confidence_weight
            + self.diversity_weight
        )

        risk = (
            self.confidence_weight * average_confidence
            + self.diversity_weight * diversity_score
        ) / weight_total

        return round(
            max(0.0, min(risk, 1.0)),
            4,
        )