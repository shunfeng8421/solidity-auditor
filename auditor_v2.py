#!/usr/bin/env python3
"""
Solidity Auditor v2 — 25 Custom Rules + 70+ Slither Detectors = 100+ total
"""
import json, os, sys, time, subprocess
from datetime import datetime, timezone, timedelta

TZ_CN = timezone(timedelta(hours=8))
from auditor import run_all_rules, audit_file as custom_audit

def combined_audit(sol_path, use_slither=True):
    """Run both custom rules and Slither on a single .sol file"""
    # Custom rules (fast, always run)
    custom = custom_audit(sol_path)

    # Slither (slower, optional)
    slither = None
    if use_slither:
        try:
            from slither_wrapper import run_slither
            slither = run_slither(sol_path, timeout=90)
        except Exception as e:
            slither = {"error": str(e)[:200]}

    # Merge findings
    all_findings = custom.get("findings", {}).get("details", [])

    slither_findings = []
    if slither and "findings" in slither:
        for f in slither["findings"]:
            f["source"] = "slither"
            slither_findings.append({
                "rule_id": f.get("rule_id", "S-?"),
                "rule_name": f.get("rule_name", "unknown"),
                "severity": f.get("severity", "low"),
                "source": "slither",
                "detail": f.get("detail", ""),
                "line": f.get("locations", [{}])[0].get("line") if f.get("locations") else None,
            })

    all_findings += slither_findings

    # Recalculate score
    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in all_findings if f.get("severity") == "high")

    return {
        "file": sol_path,
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "custom_score": custom.get("score", {}),
        "slither_summary": slither.get("summary", {}) if slither else {},
        "findings": {
            "total": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "custom": custom.get("findings", {}).get("total", 0),
            "slither": slither.get("summary", {}).get("total_findings", 0) if slither else 0,
            "details": all_findings,
        },
    }


def combined_audit_dir(dir_path, use_slither=True):
    """Audit all .sol files in a directory"""
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
        t0 = time.time()
        report = combined_audit(sol_file, use_slither=use_slither)
        elapsed = time.time() - t0
        f = report["findings"]
        print(f"{f['total']}⚠ (C:{f['custom']} S:{f['slither']}) {elapsed:.1f}s", file=sys.stderr)
        reports.append(report)

    return reports


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Solidity Auditor v2 — 100+ rules")
    ap.add_argument("--path", help="Path to .sol file")
    ap.add_argument("--dir", help="Directory with .sol files")
    ap.add_argument("--no-slither", action="store_true", help="Skip Slither")
    ap.add_argument("--output", default="audit_report_v2.json")
    args = ap.parse_args()

    use_slither = not args.no_slither

    if args.path:
        reports = [combined_audit(args.path, use_slither)]
    elif args.dir:
        reports = combined_audit_dir(args.dir, use_slither)
    else:
        ap.print_help()
        sys.exit(1)

    # Summary
    total_f = sum(r["findings"]["total"] for r in reports)
    total_crit = sum(r["findings"]["critical"] for r in reports)
    total_high = sum(r["findings"]["high"] for r in reports)

    output = {
        "auditor": "solidity-auditor v2.0 (+Slither)",
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "summary": {
            "files": len(reports),
            "total_findings": total_f,
            "critical": total_crit,
            "high": total_high,
        },
        "reports": reports,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*50}", file=sys.stderr)
    print(f"  Files: {len(reports)} | Findings: {total_f} (↓{total_crit} ↑{total_high})", file=sys.stderr)
    print(f"  Report: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
