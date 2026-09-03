from app.correlation.features import PairFeatures


def calculate_edge_weight(features: PairFeatures) -> float:
    """
    Calculate the correlation strength between two alerts.

    Higher values indicate a stronger relationship.
    """

    weight = 0.0

    # Same source host is the strongest basic relationship.
    if features.same_source:
        weight += 0.40

    # Same destination provides additional evidence.
    if features.same_destination:
        weight += 0.20

    # An uncommon destination is stronger evidence than a
    # destination shared by common infrastructure.
    if features.uncommon_destination:
        weight += 0.10

    # Same flow is a very strong direct relationship.
    if features.same_flow:
        weight += 0.25

    # Alerts deviating from their baselines in the same
    # direction provide additional correlation evidence.
    if features.same_baseline_direction:
        weight += 0.10

    # Matching protocol provides supporting correlation evidence.
    if features.same_protocol:
        weight += 0.05

    # Known shared infrastructure is weak evidence for correlation
    # and should actively reduce the edge strength.
    if features.shared_infrastructure:
        weight -= 0.15

    # Alerts occurring close together in time are more likely
    # to belong to the same incident.
    weight += 0.15 * features.temporal_proximity

    return max(0.0, min(weight, 1.0))