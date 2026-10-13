#!/usr/bin/env python3
"""Generate synthetic alert data for demos and benchmarks.

Usage:  python scripts/sample_data.py [--out alerts.jsonl] [--count 20]

All data is synthetic and fictional — no real systems or users.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta

_TEMPLATES = [
    {
        "source": "edr", "event_type": "process_start", "severity": "high",
        "process": "powershell.exe", "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA",
    },
    {
        "source": "edr", "event_type": "process_start", "severity": "critical",
        "process": "mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords",
    },
    {
        "source": "edr", "event_type": "file_access", "severity": "info",
        "process": "chrome.exe",
        "cmdline": ('"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" '
                    "--profile-directory=Default"),
    },
    {
        "source": "siem", "event_type": "user_added", "severity": "high",
        "process": "cmd.exe", "cmdline": "net user backdoor P@ssw0rd! /add",
    },
    {
        "source": "edr", "event_type": "process_start", "severity": "info",
        "process": "svchost.exe", "cmdline": "svchost.exe -k netsvcs -p",
    },
    {
        "source": "network", "event_type": "network_connection", "severity": "medium",
        "process": "chrome.exe",
        "cmdline": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=utility',
    },
]

_HOSTS = ["web-01", "laptop-17", "dc-02", "win-srv-03", "laptop-09", "web-02"]
_USERS = ["alice", "bob", "svc_web", "SYSTEM", "backup_svc", "admin"]


def generate(count: int) -> list[dict]:
    out = []
    base = datetime(2026, 10, 1, tzinfo=UTC)
    for i in range(count):
        tpl = random.choice(_TEMPLATES)
        rec = dict(tpl)
        rec["event_id"] = f"syn-{i:04d}"
        rec["timestamp"] = (base + timedelta(minutes=random.randint(0, 2880))).isoformat()
        rec["host"] = random.choice(_HOSTS)
        rec["user"] = random.choice(_USERS)
        rec["src_ip"] = random.choice(["10.0.0.5", "10.0.0.42", "127.0.0.1", "10.20.30.40"])
        rec["dst_ip"] = random.choice(["45.45.45.45", "10.20.30.40", "198.51.100.7", "127.0.0.1"])
        out.append(rec)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="alerts.jsonl")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    with open(args.out, "w", encoding="utf-8") as handle:
        for rec in generate(args.count):
            handle.write(json.dumps(rec) + "\n")
    print(f"wrote {args.count} synthetic alerts to {args.out}")


if __name__ == "__main__":
    main()
