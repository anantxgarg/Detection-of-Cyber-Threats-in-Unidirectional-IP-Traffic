import os
import json
import time
import threading
import tailer
import argparse
from pydantic import ValidationError

from .schemas import ConnRecord, DnsRecord, SslRecord, NormalizedEvent
from .redis_client import RedisManager

LOG_MAP = {
    'conn.log': ('conn', ConnRecord),
    'dns.log': ('dns', DnsRecord),
    'ssl.log': ('ssl', SslRecord),
}

def tail_file(filepath: str, log_type: str, model_class, redis_mgr: RedisManager):
    print(f"Waiting for {filepath}...")
    
    while not os.path.exists(filepath):
        time.sleep(1)
        
    print(f"Started tailing {filepath}")
    count = 0
    for line in tailer.follow(open(filepath, 'r')):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            record = model_class.model_validate(data)
            
            event = NormalizedEvent(
                log_type=log_type,
                data=record.model_dump(by_alias=True, exclude_none=True),
                ts=record.ts,
                src_ip=record.id_orig_h,
                dst_ip=record.id_resp_h,
                src_port=record.id_orig_p,
                dst_port=record.id_resp_p
            )
            redis_mgr.push_event(event)
            count += 1
            if count % 1000 == 0:
                print(f"[{log_type}] Successfully parsed and dispatched {count} events...")
        except json.JSONDecodeError:
            print(f"JSON decode error in {filepath}: {line}")
        except ValidationError as e:
            print(f"Validation error in {filepath}: {e}")
        except Exception as e:
            print(f"Error processing line in {filepath}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Tail Zeek JSON logs and stream to Redis")
    parser.add_argument("--log-dir", default="./logs", help="Directory containing Zeek logs")
    parser.add_argument("--redis-host", default="localhost", help="Redis host")
    args = parser.parse_args()

    redis_mgr = RedisManager(host=args.redis_host)
    
    threads = []
    for log_filename, (log_type, model_class) in LOG_MAP.items():
        filepath = os.path.join(args.log_dir, log_filename)
        t = threading.Thread(
            target=tail_file,
            args=(filepath, log_type, model_class, redis_mgr),
            daemon=True
        )
        t.start()
        threads.append(t)

    print("Tailer running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping tailer...")

if __name__ == "__main__":
    main()
