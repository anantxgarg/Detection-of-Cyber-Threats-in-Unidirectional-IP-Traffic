from __future__ import annotations

import time

from app.redis_listener import AlertStreamListener


def run() -> None:
    """
    Continuously consume alerts from Redis and process them.
    """

    listener = AlertStreamListener()

    print("Correlation and risk engine started.")
    print("Listening on Redis stream: alerts:live")

    while True:
        try:
            incidents = listener.process_batch()

            for incident in incidents:
                print(
                    f"Incident detected | "
                    f"id={incident.incident_id} | "
                    f"risk={incident.risk} | "
                    f"alerts={len(incident.alerts)} | "
                    f"threats={incident.threat_types}"
                )

        except Exception as exc:
            print(f"Error while processing alerts: {exc}")

            time.sleep(2)


if __name__ == "__main__":
    run()