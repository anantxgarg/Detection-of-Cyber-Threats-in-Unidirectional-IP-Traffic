import os

from ollama import chat

from app.schemas.incident import Incident


DEFAULT_MODEL = "qwen3:1.7b"


def build_incident_prompt(incident: Incident) -> str:
    """
    Build a grounded prompt from structured incident data.

    The LLM is only responsible for generating a human-readable
    narrative. It must not change detection results, confidence,
    risk, or ATT&CK mappings.
    """

    evidence_lines = []

    for key, value in incident.evidence.items():
        evidence_lines.append(f"{key}: {value}")

    correlation_facts = []

    # Shared source
    source_ips = {
        alert.src_ip
        for alert in incident.alerts
        if alert.src_ip
    }

    if len(source_ips) == 1:
        correlation_facts.append(
            f"Shared source IP: {next(iter(source_ips))}"
        )

    # Shared destination
    destination_ips = {
        alert.dst_ip
        for alert in incident.alerts
        if alert.dst_ip
    }

    if len(destination_ips) == 1:
        correlation_facts.append(
            f"Shared destination IP: {next(iter(destination_ips))}"
        )

    # Shared flow
    flow_ids = {
        alert.flow_id
        for alert in incident.alerts
        if alert.flow_id
    }

    if len(flow_ids) == 1:
        correlation_facts.append(
            f"Shared flow ID: {next(iter(flow_ids))}"
        )

    # Incident time span
    timestamps = [
        alert.timestamp
        for alert in incident.alerts
        if alert.timestamp is not None
    ]

    if len(timestamps) >= 2:
        correlation_facts.append(
            f"Incident alert time span: "
            f"{max(timestamps) - min(timestamps):.1f} seconds"
        )

    if not correlation_facts:
        correlation_facts.append(
            "No explicit shared relationships supplied."
        )

    attack_techniques = [
        f"{technique['technique_id']} - "
        f"{technique['technique_name']}"
        for technique in incident.attack_techniques
    ]

    prompt = f"""
You are a cybersecurity incident reporting assistant.

Convert the supplied incident data into a SHORT,
STRUCTURED cybersecurity report.

Use ONLY the information provided.

Incident ID:
{incident.incident_id}

Risk Score:
{incident.risk}

Threat Types:
{incident.threat_types}

ATT&CK Techniques:
{attack_techniques}

Evidence:
{evidence_lines}

INCIDENT-LEVEL CORRELATION FACTS:

{correlation_facts}

IMPORTANT CORRELATION RULES:

The Evidence section contains information belonging
to individual alerts.

A field appearing in one alert does NOT mean that
the field is shared across the incident.

A field may be described as "shared" ONLY when it
appears in the INCIDENT-LEVEL CORRELATION FACTS.

Never infer a shared relationship from the Evidence
section yourself.

OUTPUT FORMAT

## INCIDENT SUMMARY

| Field | Value |
|---|---|
| Incident ID | value |
| Risk Score | value |
| Threat Types | values |

## THREATS DETECTED

| Threat Type | Confidence | Source IP | Destination IP |
|---|---:|---|---|

Include only values actually present.
Use "-" when unavailable.

## DETECTION FEATURES

| Threat Type | Feature | Value |
|---|---|---|

List actual evidence fields and values.
Do not combine evidence from different alerts.

## CORRELATION

| Feature | Value |
|---|---|

Include ONLY relationships explicitly present
in INCIDENT-LEVEL CORRELATION FACTS.

## ATT&CK MAPPING

| Technique ID | Technique Name | Description |
|---|---|---|

Use ONLY the supplied ATT&CK techniques.
Do not create new techniques.

## ANALYST ATTENTION

Provide 1-3 concise bullet points.

Do not claim confirmed compromise.
Do not claim malicious intent unless explicitly supplied.
Do not change confidence.
Do not change risk.
Do not create new ATT&CK techniques.
Do not add unsupported relationships.
Do not treat per-alert fields as incident-level facts.
Only use shared relationships explicitly supplied.
Use "-" when unavailable.
Remain concise.
"""

    return prompt.strip()


def generate_narrative(incident: Incident) -> str:
    """
    Generate an optional LLM narrative.

    The LLM is strictly an enrichment layer.
    It must never block or affect the core
    detection/correlation/risk pipeline.
    """

    model = os.getenv(
        "OLLAMA_MODEL",
        DEFAULT_MODEL,
    )

    try:
        response = chat(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity incident "
                        "reporting assistant. Convert structured "
                        "security findings into concise Markdown "
                        "tables and short bullet points. "
                        "Remain strictly grounded in the supplied "
                        "data. Never invent facts, intent, attack "
                        "stages, infrastructure roles, or "
                        "compromise claims. "
                        "Never treat a field from one alert as "
                        "shared incident-level evidence unless "
                        "the supplied correlation facts explicitly "
                        "establish that relationship."
                    ),
                },
                {
                    "role": "user",
                    "content": build_incident_prompt(incident),
                },
            ],
            think=False,
            options={
                "num_predict": 300,
            },
        )

        return response.message.content

    except Exception:
        # LLM is optional enrichment.
        # Never allow an LLM failure to affect
        # detection, correlation, risk, evidence,
        # or ATT&CK mapping.
        return ""