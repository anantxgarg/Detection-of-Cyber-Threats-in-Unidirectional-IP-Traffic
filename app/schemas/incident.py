from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.schemas.alert import Alert


class Incident(BaseModel):
    """
    Represents a correlated security incident.
    """

    incident_id: str
    alerts: list[Alert] = Field(default_factory=list)
    threat_types: list[str] = Field(default_factory=list)
    risk: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[dict[str, str]] = Field(
        default_factory=list
    )
    narrative: str = ""