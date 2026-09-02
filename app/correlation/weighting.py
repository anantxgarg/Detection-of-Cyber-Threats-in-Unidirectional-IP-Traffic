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

    # Same flow is a very strong direct relationship.
    if features.same_flow:
        weight += 0.25

    # Alerts occurring close together in time are more likely
    # to belong to the same incident.
    weight += 0.15 * features.temporal_proximity

    return min(weight, 1.0)