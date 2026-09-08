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
    uncommon_destination: bool
    same_baseline_direction: bool
    shared_infrastructure: bool
    same_protocol: bool


def _destination_is_uncommon(alert: Alert) -> bool:
    """
    Return whether an alert provides evidence that its destination
    is uncommon.

    This is intentionally optional. Existing detectors that do not
    provide destination-rarity evidence simply return False.
    """

    evidence = alert.evidence

    rarity = evidence.get("destination_rarity")

    if isinstance(rarity, (int, float)):
        return float(rarity) >= 0.7

    uncommon = evidence.get("uncommon_destination")

    if isinstance(uncommon, bool):
        return uncommon

    return False


def _baseline_direction(alert: Alert) -> str | None:
    """
    Return the baseline-deviation direction provided by an alert.

    Supported values are:
    - "above"
    - "below"

    Alerts without this evidence return None.
    """

    direction = alert.evidence.get(
        "baseline_deviation_direction"
    )

    if isinstance(direction, str):
        direction = direction.strip().lower()

        if direction in {"above", "below"}:
            return direction

    return None


def _shared_infrastructure(alert: Alert) -> bool:
    """
    Return whether an alert identifies its destination as
    known shared infrastructure.

    This is intentionally optional. Existing detectors that do not
    provide this evidence simply return False.
    """

    value = alert.evidence.get("shared_infrastructure")

    return isinstance(value, bool) and value


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

    time_delta = abs(
        alert_a.timestamp - alert_b.timestamp
    )

    if temporal_window > 0:
        temporal_proximity = max(
            0.0,
            1.0 - (time_delta / temporal_window),
        )
    else:
        temporal_proximity = 0.0

    same_source = (
        alert_a.src_ip == alert_b.src_ip
    )

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

    same_protocol = (
        alert_a.protocol is not None
        and alert_b.protocol is not None
        and alert_a.protocol == alert_b.protocol
    )

    different_threat_class = (
        alert_a.threat_class != alert_b.threat_class
    )

    uncommon_destination = (
        same_destination
        and _destination_is_uncommon(alert_a)
        and _destination_is_uncommon(alert_b)
    )

    direction_a = _baseline_direction(alert_a)
    direction_b = _baseline_direction(alert_b)

    same_baseline_direction = (
        direction_a is not None
        and direction_b is not None
        and direction_a == direction_b
    )

    shared_infrastructure = (
        same_destination
        and (
            _shared_infrastructure(alert_a)
            or _shared_infrastructure(alert_b)
        )
    )

    return PairFeatures(
        time_delta=time_delta,
        temporal_proximity=temporal_proximity,
        same_source=same_source,
        same_destination=same_destination,
        same_flow=same_flow,
        different_threat_class=different_threat_class,
        uncommon_destination=uncommon_destination,
        same_baseline_direction=same_baseline_direction,
        shared_infrastructure=shared_infrastructure,
        same_protocol=same_protocol,
    )