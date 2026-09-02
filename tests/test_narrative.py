from app.narrative.generator import (
    build_incident_prompt,
    generate_narrative,
)
from app.schemas.incident import Incident


def make_incident() -> Incident:
    return Incident(
        incident_id="test-incident",
        threat_types=[
            "Recon/Scanning",
            "C2 Beaconing",
        ],
        risk=0.82,
        evidence={
            "Recon/Scanning_1": {
                "confidence": 0.85,
                "detector_evidence": {
                    "unique_ports_scanned": 25
                },
            }
        },
        attack_techniques=[
            {
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
            }
        ],
    )


def test_incident_prompt_contains_security_context():
    incident = make_incident()

    prompt = build_incident_prompt(incident)

    assert "test-incident" in prompt
    assert "Recon/Scanning" in prompt
    assert "C2 Beaconing" in prompt
    assert "0.82" in prompt
    assert "T1046" in prompt
    assert "Network Service Scanning" in prompt


def test_generate_narrative_uses_local_llm(monkeypatch):
    incident = make_incident()

    class FakeMessage:
        content = (
            "The incident contains reconnaissance "
            "and C2-related behavioral alerts."
        )

    class FakeResponse:
        message = FakeMessage()

    def fake_chat(**kwargs):
        assert kwargs["model"] == "qwen3:1.7b"

        messages = kwargs["messages"]

        assert "Recon/Scanning" in messages[1]["content"]
        assert "T1046" in messages[1]["content"]

        return FakeResponse()

    monkeypatch.setattr(
        "app.narrative.generator.chat",
        fake_chat,
    )

    narrative = generate_narrative(incident)

    assert "reconnaissance" in narrative
    assert "C2" in narrative