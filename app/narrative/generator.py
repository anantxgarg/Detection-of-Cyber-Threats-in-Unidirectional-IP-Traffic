from __future__ import annotations

import os

from ollama import chat

from app.schemas.incident import Incident


DEFAULT_MODEL = "qwen3:1.7b"


def build_incident_prompt(incident: Incident) -> str:
    evidence_text = []

    for name, evidence in incident.evidence.items():
        evidence_text.append(
            f"{name}: {evidence}"
        )

    attack_text = []

    for technique in incident.attack_techniques:
        attack_text.append(
            f"{technique['technique_id']} - "
            f"{technique['technique_name']}"
        )

    # ---------------------------------------------------------
    # Build incident-level correlation facts.
    #
    # IMPORTANT:
    # A field is "shared" only when EVERY alert contains
    # that field and all alerts have the same value.
    # ---------------------------------------------------------

    correlation_facts = []

    alerts = incident.alerts

    if alerts:

        # Shared source IP
        source_ips = [
            alert.src_ip
            for alert in alerts
            if alert.src_ip is not None
        ]

        if (
            len(source_ips) == len(alerts)
            and len(set(source_ips)) == 1
        ):
            correlation_facts.append(
                f"Shared source IP: {source_ips[0]}"
            )

        # Shared destination IP
        destination_ips = [
            alert.dst_ip
            for alert in alerts
        ]

        if (
            len(destination_ips) == len(alerts)
            and all(
                destination_ip is not None
                for destination_ip in destination_ips
            )
            and len(set(destination_ips)) == 1
        ):
            correlation_facts.append(
                f"Shared destination IP: "
                f"{destination_ips[0]}"
            )

        # Shared flow ID
        flow_ids = [
            alert.flow_id
            for alert in alerts
        ]

        if (
            len(flow_ids) == len(alerts)
            and all(
                flow_id is not None
                for flow_id in flow_ids
            )
            and len(set(flow_ids)) == 1
        ):
            correlation_facts.append(
                f"Shared flow ID: {flow_ids[0]}"
            )

        # Incident time span
        timestamps = [
            alert.timestamp
            for alert in alerts
        ]

        if len(timestamps) > 1:
            time_span = max(timestamps) - min(timestamps)

            correlation_facts.append(
                f"Incident alert time span: "
                f"{round(time_span, 2)} seconds"
            )

    if not correlation_facts:
        correlation_facts.append(
            "No explicit incident-level correlation "
            "relationship is available."
        )

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
{attack_text}

Evidence:
{evidence_text}

INCIDENT-LEVEL CORRELATION FACTS:

{correlation_facts}

IMPORTANT CORRELATION RULES:

The Evidence section contains information belonging
to individual alerts.

A field appearing in one alert does NOT mean that
the field is shared across the incident.

A field may be described as "shared" ONLY when it
appears in the INCIDENT-LEVEL CORRELATION FACTS.

For example:

Alert 1:
destination IP = None

Alert 2:
destination IP = 66.94.238.147

This is NOT a shared destination IP.

Likewise:

Alert 1:
flow ID = None

Alert 2:
flow ID = ABC

This is NOT a shared flow.

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

Create ONE table containing the detected threats.

| Threat Type | Confidence | Source IP | Destination IP |
|---|---:|---|---|

Include only values actually present.

Use "-" when unavailable.

## DETECTION FEATURES

Create ONE table:

| Threat Type | Feature | Value |
|---|---|---|

List actual evidence fields and values.

Do not combine evidence from different alerts.

## CORRELATION

Create a small table:

| Feature | Value |
|---|---|

Use ONLY the INCIDENT-LEVEL CORRELATION FACTS.

Do NOT derive correlation relationships yourself.

Do NOT call a destination IP shared unless it
appears in the correlation facts.

Do NOT call a flow ID shared unless it appears
in the correlation facts.

If no relationship is provided, state that no
explicit relationship is available.

## ATT&CK MAPPING

Create ONE table:

| Technique ID | Technique Name | Description |
|---|---|---|

Use ONLY the supplied ATT&CK techniques.

Do not create additional techniques.

Do not claim that a technique proves malicious
intent or compromise.

The description must only explain the supplied
mapping.

## ANALYST ATTENTION

No more than TWO short bullet points.

Only recommend actions directly supported by the
supplied evidence.

STRICT RULES

- Markdown tables
- no long paragraphs
- no repeated "parameter"
- use only supplied information
- no invented facts
- no invented intent
- no invented attack stages
- do not assume destination IP is C2
- do not call an IP malicious unless explicitly stated
- do not infer malware
- do not infer compromise
- do not infer vulnerabilities
- do not infer APT activity
- do not infer exfiltration
- preserve evidence terminology exactly
- do not reinterpret "cov"
- do not change risk
- do not change confidence
- do not create new ATT&CK techniques
- do not add unsupported relationships
- do not treat per-alert fields as incident-level facts
- only use shared relationships explicitly supplied
- use "-" when unavailable
- remain concise
"""

    return prompt.strip()


def generate_narrative(incident: Incident) -> str:
    """
    Generate an optional LLM narrative.

    The LLM is an enrichment layer only.
    It does not determine threat class, confidence,
    or risk.
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
        )

        return response.message.content

    except Exception as exc:
        # The LLM must never break the detection pipeline.
        return (
            "LLM narrative unavailable. "
            f"Reason: {type(exc).__name__}"
        )