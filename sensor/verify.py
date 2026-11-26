"""Check Suricata alerts and confirm that every fixture flow was observed."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from fixtures import CLIENT_IP, FIRST_CLIENT_PORT, SERVER_IP, scenarios


def fixture_port(event: dict) -> int | None:
    if event.get("src_ip") == CLIENT_IP and event.get("dest_ip") == SERVER_IP:
        return event.get("src_port")
    if event.get("src_ip") == SERVER_IP and event.get("dest_ip") == CLIENT_IP:
        return event.get("dest_port")
    return None


def verify(path: Path) -> dict:
    expected = {FIRST_CLIENT_PORT + offset: case for offset, case in enumerate(scenarios())}
    alerts = defaultdict(set)
    observed_flows = set()
    with path.open(encoding="utf-8") as eve:
        for line_number, line in enumerate(eve, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError(f"EVE line {line_number} is not an object")
            port = fixture_port(event)
            if event.get("event_type") == "flow" and port in expected:
                observed_flows.add(port)
            if event.get("event_type") == "alert":
                alert = event.get("alert")
                if not isinstance(alert, dict) or type(alert.get("signature_id")) is not int:
                    raise ValueError(f"EVE line {line_number} has an invalid alert signature ID")
                alerts[port].add(alert["signature_id"])

    missing = []
    unexpected = []
    observed_rule_count = 0
    for port, case in expected.items():
        if case.expected_sid is not None:
            if case.expected_sid in alerts[port]:
                observed_rule_count += 1
            else:
                missing.append({"scenario": case.name, "signature_id": case.expected_sid})
        for sid in sorted(alerts[port] - {case.expected_sid}):
            unexpected.append({"scenario": case.name, "signature_id": sid})
    for port, found in alerts.items():
        if port not in expected:
            for sid in sorted(found):
                unexpected.append({"scenario": "outside-fixture", "source_port": port, "signature_id": sid})

    missing_flows = [case.name for port, case in expected.items() if port not in observed_flows]
    control_flow_count = sum(case.expected_sid is None for case in expected.values())
    observed_control_flow_count = sum(expected[port].expected_sid is None for port in observed_flows)
    return {
        "passed": not (missing or unexpected or missing_flows),
        "expected_rule_count": len(expected) - control_flow_count,
        "observed_rule_count": observed_rule_count,
        "control_flow_count": control_flow_count,
        "observed_control_flow_count": observed_control_flow_count,
        "missing": missing,
        "unexpected": unexpected,
        "missing_flows": missing_flows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eve", type=Path, help="Suricata eve.json")
    args = parser.parse_args()
    try:
        verdict = verify(args.eve)
    except (OSError, ValueError) as error:
        print(f"Cannot verify {args.eve}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
