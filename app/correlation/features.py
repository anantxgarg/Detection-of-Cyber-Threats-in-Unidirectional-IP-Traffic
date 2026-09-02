from __future__ import annotations

from dataclasses import dataclass

from app.schemas.alert import Alert


@dataclass(frozen=True)
class PairFeatures:
    """Relationship features between two alerts."""

    time_delta: float
    temporal_proximity: float
    same_source: bool
    same_destination: bool
    same_flow: bool
    different_threat_class: bool


def compute_pair_features(
    alert_a: Alert,
    alert_b: Alert,
    temporal_window: float = 300.0,
) -> PairFeatures:
    """
    Compute relationship features for a pair of alerts.

    These features describe how strongly two alerts are related.
    They do not calculate a final correlation weight.
    """

    time_delta = abs(alert_a.timestamp - alert_b.timestamp)

    if temporal_window > 0:
        temporal_proximity = max(
            0.0,
            1.0 - (time_delta / temporal_window),
        )
    else:
        temporal_proximity = 0.0

    same_source = alert_a.src_ip == alert_b.src_ip

    same_destination = (
        alert_a.dst_ip is not None
        and alert_b.dst_ip is not None
        and alert_a.dst_ip == alert_b.dst_ip
    )

    same_flow = (
        alert_a.flow_id is not None
        and alert_b.flow_id is not None
        and alert_a.flow_id == alert_b.flow_id
    )

    different_threat_class = (
        alert_a.threat_class != alert_b.threat_class
    )

    return PairFeatures(
        time_delta=time_delta,
        temporal_proximity=temporal_proximity,
        same_source=same_source,
        same_destination=same_destination,
        same_flow=same_flow,
        different_threat_class=different_threat_class,
    )