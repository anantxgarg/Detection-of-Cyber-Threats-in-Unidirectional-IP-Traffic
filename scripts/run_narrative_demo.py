from app.main import process_alerts


def main() -> None:
    alerts = [
        """
        {
            "timestamp": 1000,
            "src_ip": "10.0.0.5",
            "dst_ip": null,
            "flow_id": "scan-1",
            "threat_class": "Recon/Scanning",
            "confidence": 0.85,
            "evidence": {
                "unique_ports_scanned": 25,
                "window_seconds": 60
            }
        }
        """,
        """
        {
            "timestamp": 1050,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.20",
            "flow_id": "c2-1",
            "threat_class": "C2 Beaconing",
            "confidence": 0.80,
            "evidence": {
                "cov": 0.1,
                "mean_interval_sec": 60
            }
        }
        """
    ]

    incidents = process_alerts(
        alerts,
        generate_llm_narrative=True,
    )

    if not incidents:
        raise RuntimeError("No incident was created.")

    incident = incidents[0]

    print("\n" + "=" * 60)
    print("INCIDENT")
    print("=" * 60)

    print(f"Incident ID : {incident.incident_id}")
    print(f"Risk        : {incident.risk}")
    print(f"Threats     : {incident.threat_types}")

    print("\nATT&CK Techniques:")

    for technique in incident.attack_techniques:
        print(
            f"  {technique['technique_id']} - "
            f"{technique['technique_name']}"
        )

    print("\n" + "=" * 60)
    print("LLM INCIDENT NARRATIVE")
    print("=" * 60)

    print(incident.narrative)

    print("=" * 60)


if __name__ == "__main__":
    main()