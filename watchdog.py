#!/usr/bin/env python3
"""
Watchdog Mode — 对标 Codex passive detection
实时监控文件变化，发现安全问题即时告警
"""
import os
import sys
import time
import json
from datetime import datetime, timezone, timedelta

TZ_CN = timezone(timedelta(hours=8))


def watch_directory(dir_path: str, interval: int = 5):
    """
    Watch a directory for changes to .sol files.
    When a file changes, re-audit it and report findings.
    """
    print(f"🔍 Watching {dir_path} (every {interval}s)...", file=sys.stderr)

    # Track file states
    file_states = {}
    sol_files = _find_sol_files(dir_path)
    for sf in sol_files:
        file_states[sf] = os.path.getmtime(sf)

    while True:
        time.sleep(interval)
        current_files = _find_sol_files(dir_path)

        for sf in current_files:
            mtime = os.path.getmtime(sf)
            if sf not in file_states:
                # New file
                file_states[sf] = mtime
                _audit_and_report(sf, "NEW FILE")
            elif mtime != file_states[sf]:
                # Modified file
                file_states[sf] = mtime
                _audit_and_report(sf, "MODIFIED")


def _find_sol_files(dir_path: str) -> list:
    files = []
    for root, _, fs in os.walk(dir_path):
        if ".git" in root or "node_modules" in root: continue
        for f in fs:
            if f.endswith(".sol"):
                files.append(os.path.join(root, f))
    return files


def _audit_and_report(filepath: str, event: str):
    """Run audit and report critical/high findings"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from auditor_v3 import full_audit

    report = full_audit(filepath)
    findings = report.get("findings", {})
    critical = [f for f in findings.get("details", []) if f["severity"] == "critical"]
    high = [f for f in findings.get("details", []) if f["severity"] == "high"]

    if critical or high:
        ts = datetime.now(TZ_CN).strftime("%H:%M:%S")
        rel = os.path.basename(filepath)
        print(f"\n🚨 [{ts}] {event}: {rel}", file=sys.stderr)
        print(f"   ↓{len(critical)} critical  ↑{len(high)} high", file=sys.stderr)
        for f in critical[:3]:
            print(f"   ⚡ {f['name']}: {f['detail'][:100]}", file=sys.stderr)
        for f in high[:3]:
            print(f"   ⚠️  {f['name']}: {f['detail'][:100]}", file=sys.stderr)

        # Save to event log
        log_entry = {
            "timestamp": datetime.now(TZ_CN).isoformat(),
            "event": event,
            "file": filepath,
            "critical": len(critical),
            "high": len(high),
        }
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "watchdog_events.jsonl")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Solidity Watchdog — passive detection")
    ap.add_argument("--dir", required=True, help="Directory to watch")
    ap.add_argument("--interval", type=int, default=10, help="Poll interval in seconds")
    args = ap.parse_args()

    watch_directory(args.dir, args.interval)
