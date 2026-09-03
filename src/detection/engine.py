import redis
import json
import time
import argparse

from src.ingestion.schemas import NormalizedEvent
from src.detection.baseline import BaselineEngine
from src.detection.detectors.recon import ReconDetector
from src.detection.detectors.c2_beaconing import C2BeaconingDetector
from src.detection.detectors.dga import DGADetector
from src.detection.detectors.dns_tunnel import DNSTunnelDetector
from src.detection.detectors.ddos import DDoSDetector
from src.detection.detectors.exfiltration import ExfiltrationDetector
from src.detection.detectors.encrypted_anomaly import EncryptedAnomalyDetector


class DetectionEngine:
    def __init__(self, redis_host="localhost"):
        self.r = redis.Redis(
            host=redis_host,
            decode_responses=True,
        )

        self.baseline = BaselineEngine(
            host=redis_host,
        )

        self.detectors = [
            ReconDetector(self.r),
            C2BeaconingDetector(self.r),
            DGADetector(),
            DNSTunnelDetector(self.r),
            DDoSDetector(self.r, self.baseline),
            ExfiltrationDetector(self.r, self.baseline),
            EncryptedAnomalyDetector(self.r, self.baseline),
        ]

    def run(self):
        print(
            "Detection Engine started. "
            "Listening to events:live..."
        )

        last_id = "$"

        while True:
            try:
                streams = self.r.xread(
                    {"events:live": last_id},
                    count=100,
                    block=1000,
                )

                if not streams:
                    continue

                for stream_name, messages in streams:
                    for msg_id, msg_data in messages:
                        last_id = msg_id

                        try:
                            # Reconstruct event mapping from Redis
                            # string values.
                            event_data = dict(msg_data)

                            event_data["data"] = json.loads(
                                msg_data["data"]
                            )

                            event_data["ts"] = float(
                                msg_data["ts"]
                            )

                            event_data["src_port"] = int(
                                msg_data["src_port"]
                            )

                            event_data["dst_port"] = int(
                                msg_data["dst_port"]
                            )

                            event = NormalizedEvent.model_validate(
                                event_data
                            )

                            # Update the host-adaptive baseline.
                            self.baseline.update_from_event(event)

                            # Run all detectors.
                            for detector in self.detectors:
                                result = detector.analyze(event)

                                if result:
                                    # Carry the protocol from the
                                    # triggering Zeek event into the
                                    # detection result when available.
                                    protocol = event.data.get("proto")

                                    if isinstance(protocol, str):
                                        protocol = protocol.strip().lower()
                                    else:
                                        protocol = None

                                    result = result.model_copy(
                                        update={
                                            "protocol": protocol,
                                        }
                                    )

                                    print(
                                        f"🔥 ALERT "
                                        f"[{result.threat_class.value}] "
                                        f"Confidence: "
                                        f"{result.confidence} "
                                        f"Target: "
                                        f"{result.src_ip}"
                                    )

                                    self.r.xadd(
                                        "alerts:live",
                                        {
                                            "alert": (
                                                result.model_dump_json()
                                            )
                                        },
                                    )

                        except Exception as e:
                            print(
                                f"Error processing event "
                                f"{msg_id}: {e}"
                            )

            except redis.ConnectionError:
                print(
                    "Redis connection error. Retrying..."
                )
                time.sleep(2)

            except KeyboardInterrupt:
                print("Stopping engine.")
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--redis-host",
        default="localhost",
    )

    args = parser.parse_args()

    engine = DetectionEngine(
        redis_host=args.redis_host,
    )

    engine.run()