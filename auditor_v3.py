#!/usr/bin/env python3
"""
Solidity Auditor v3 — Full Engine
50 regex rules + CEI checker + 25 vulnerability signatures = 75+ checks
"""
import json, os, sys, time
from datetime import datetime, timezone, timedelta

TZ_CN = timezone(timedelta(hours=8))

def full_audit(filepath: str) -> dict:
    t0 = time.time()

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    # Layer 1: 50 regex rules
    from auditor import run_all_rules
    rule_results = run_all_rules(code, os.path.basename(filepath))

    # Layer 2: Deep CEI + signature scan
    from deep_audit import deep_audit as deep_scan
    deep_results = deep_scan(code)

    # Merge all findings
    all_findings = []
    for r in rule_results:
        if not r.get("pass"):
            all_findings.append({
                "source": "rule",
                "rule_id": r["rule_id"],
                "name": r["rule_name"],
                "severity": r["severity"],
                "detail": r.get("detail", ""),
            })

    for f in deep_results.get("findings", []):
        all_findings.append({
            "source": "deep",
            "name": f.get("name", f.get("type", "?")),
            "severity": f.get("severity", "low"),
            "detail": f.get("detail", f.get("description", "")),
            "sig_id": f.get("sig_id"),
        })

    # Counts
    critical = sum(1 for f in all_findings if f["severity"] == "critical")
    high = sum(1 for f in all_findings if f["severity"] == "high")
    medium = sum(1 for f in all_findings if f["severity"] == "medium")

    return {
        "file": filepath,
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "findings": {
            "total": len(all_findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "rule_findings": sum(1 for f in all_findings if f["source"] == "rule"),
            "deep_findings": sum(1 for f in all_findings if f["source"] == "deep"),
            "details": all_findings,
        },
        "meta": {"elapsed_s": round(time.time() - t0, 1)},
    }


def batch_audit(dir_path: str) -> list:
    reports = []
    sol_files = []
    for root, _, files in os.walk(dir_path):
        if ".git" in root or "node_modules" in root:
            continue
        for f in files:
            if f.endswith(".sol"):
                sol_files.append(os.path.join(root, f))

    for i, sol_file in enumerate(sol_files):
        rel = os.path.relpath(sol_file, dir_path)
        print(f"  [{i+1}/{len(sol_files)}] {rel} ...", file=sys.stderr, end=" ")
        report = full_audit(sol_file)
        f = report["findings"]
        print(f"{f['total']}⚠ (↓{f['critical']} ↑{f['high']}) {report['meta']['elapsed_s']}s", file=sys.stderr)
        reports.append(report)

    return reports


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Solidity Auditor v3 — 75+ checks")
    ap.add_argument("--path")
    ap.add_argument("--dir")
    ap.add_argument("--output", default="audit_v3.json")
    args = ap.parse_args()

    if args.path:
        reports = [full_audit(args.path)]
    elif args.dir:
        reports = batch_audit(args.dir)
    else:
        ap.print_help(); sys.exit(1)

    total = sum(r["findings"]["total"] for r in reports)
    crit = sum(r["findings"]["critical"] for r in reports)
    high = sum(r["findings"]["high"] for r in reports)

    output = {
        "auditor": "solidity-auditor v3.0 (50 rules + CEI + 25 sigs)",
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "summary": {"files": len(reports), "total_findings": total, "critical": crit, "high": high},
        "reports": reports,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*50}", file=sys.stderr)
    print(f"  Files: {len(reports)} | Findings: {total} (↓{crit} ↑{high})", file=sys.stderr)
    print(f"  Report: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
