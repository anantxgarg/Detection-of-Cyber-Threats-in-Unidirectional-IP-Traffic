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

## CORRELATION

Create a small table:

| Feature | Value |
|---|---|

Only include relationships supported by incident data,
such as shared source IP, shared destination, shared flow,
or temporal relationship.

If relationship cannot be determined, do not invent it.

## ATT&CK MAPPING

Create ONE table:

| Technique ID | Technique Name | Description |
|---|---|---|

Description should be one short sentence explaining
the existing mapping.

Do not create additional ATT&CK techniques.

## ANALYST ATTENTION

No more than TWO short bullet points.

Only recommend actions supported by supplied evidence.

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
- use "-" when unavailable
- remain concise
"""

    return prompt.strip()


def generate_narrative(incident: Incident) -> str:
    """
    Generate an optional LLM narrative.

    The LLM is an enrichment layer only.
    It does not determine threat class, confidence, or risk.
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
                        "compromise claims."
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