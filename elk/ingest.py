#!/usr/bin/env python3
"""Send Suricata EVE events to Logstash and verify the indexed run."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4


LOGSTASH_URL = "http://127.0.0.1:8088/"
INDEX = "soc-suricata-v1"
SEARCH_URL = f"http://127.0.0.1:9200/{INDEX}/_search?ignore_unavailable=true"
HTTP = build_opener(ProxyHandler({}))
BATCH_SIZE = 50


def read_eve(path):
    events = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path.name}, строка {number}: {error.msg}") from error

            if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
                raise ValueError(f"{path.name}, строка {number}: нужен EVE event_type")
            events.append(event)

    if not events:
        raise ValueError(f"В {path.name} нет событий EVE")
    return events


def post_json(url, payload, deadline):
    body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"})

    while True:
        try:
            with HTTP.open(request, timeout=5) as response:
                return response.read()
        except HTTPError as error:
            message = f"HTTP {error.code}"
            error.close()
            if error.code not in {429, 502, 503, 504}:
                raise RuntimeError(f"{url}: {message}") from error
        except (URLError, ConnectionError, TimeoutError) as error:
            message = str(error)

        if time.monotonic() >= deadline:
            raise RuntimeError(f"Сервис {url} недоступен: {message}")
        time.sleep(1)


def send_batches(events, run_id, deadline):
    for offset in range(0, len(events), BATCH_SIZE):
        batch = [
            {
                "lab_run_id": run_id,
                "lab_record_id": f"{run_id}-{number}",
                "suricata": event,
            }
            for number, event in enumerate(events[offset:offset + BATCH_SIZE], start=offset)
        ]
        post_json(LOGSTASH_URL, batch, deadline)


def indexed_counts(run_id, deadline):
    query = {
        "size": 0,
        "query": {"term": {"lab_run_id": run_id}},
        "aggs": {"event_types": {"terms": {"field": "suricata.event_type", "size": 100}}},
    }
    result = json.loads(post_json(SEARCH_URL, query, deadline))
    buckets = result.get("aggregations", {}).get("event_types", {}).get("buckets", [])
    return {item["key"]: item["doc_count"] for item in buckets}


def ingest(path, timeout):
    events = read_eve(path)
    expected = Counter(event["event_type"] for event in events)
    run_id = uuid4().hex

    send_batches(events, run_id, time.monotonic() + timeout)
    deadline = time.monotonic() + timeout
    while True:
        observed = indexed_counts(run_id, deadline)
        if observed == expected:
            return {
                "run_id": run_id,
                "index": INDEX,
                "events_indexed": len(events),
                "alerts_indexed": expected["alert"],
                "event_types": observed,
            }
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"Проверка {run_id}: ожидалось {dict(expected)}, найдено {observed}. "
                "Проверь журналы Logstash и Elasticsearch."
            )
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve_file", type=Path)
    parser.add_argument("--timeout", type=int, default=180, help="seconds per phase")
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")

    try:
        summary = ingest(args.eve_file, args.timeout)
    except (OSError, ValueError, RuntimeError) as error:
        print(error, file=sys.stderr)
        return 1

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
