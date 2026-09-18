from app.redis_listener import AlertStreamListener


def print_incident(prefix, incident):
    print(
        prefix,
        incident.incident_id,
        "| alerts=",
        len(incident.alerts),
        "| risk=",
        incident.risk,
        "| types=",
        incident.threat_types,
    )


def main():
    listener = AlertStreamListener(
        start_from_beginning=True,
        generate_llm_narrative=False,
    )

    previous_state = {}

    batch_number = 0

    while True:
        batch = listener.process_batch(count=5)

        if not batch:
            break

        batch_number += 1

        print()
        print(f"=== BATCH {batch_number} ===")
        print("New/updated incidents:", len(batch))
        print("Stored incidents:", len(listener.get_incidents()))

        for incident in batch:
            current_alert_count = len(incident.alerts)

            previous_alert_count = previous_state.get(
                incident.incident_id
            )

            if previous_alert_count is None:
                print_incident("NEW:", incident)

            elif current_alert_count > previous_alert_count:
                print_incident("UPDATED:", incident)

            else:
                print_incident("UNCHANGED:", incident)

            previous_state[incident.incident_id] = (
                current_alert_count
            )

    print()
    print("=== FINAL INCIDENT STATE ===")
    print("Total incidents:", len(listener.get_incidents()))

    for incident in listener.get_incidents():
        print_incident("FINAL:", incident)


if __name__ == "__main__":
    main()