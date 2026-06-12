#!/usr/bin/env python3
"""
Solidity Auditor — Core Engine
25 security rules × 100 points

Usage:
  python auditor.py --path contract.sol       # Single file
  python auditor.py --repo owner/repo          # Clone + audit all .sol
  python auditor.py --dir /path/to/contracts   # Directory audit
"""
import json, os, re, sys, subprocess, time
from datetime import datetime, timezone, timedelta

TZ_CN = timezone(timedelta(hours=8))

def run_all_rules(code, filename, ctx=None):
    from rules.solidity_rules import RULES
    from rules.defi_rules import DEFI_RULES
    all_rules = RULES + DEFI_RULES
    results = []
    for rule in all_rules:
        try:
            result = rule["check"](code, filename, ctx or {})
            result["rule_id"] = rule["id"]
            result["rule_name"] = rule["name"]
            result["category"] = rule["category"]
            result["severity"] = rule["severity"]
            result["max_score"] = rule["max_score"]
            result["score"] = result.get("score", 0)
            results.append(result)
        except Exception as e:
            results.append({
                "rule_id": rule["id"], "rule_name": rule["name"],
                "category": rule["category"], "severity": rule["severity"],
                "max_score": rule["max_score"], "pass": False, "score": 0,
                "detail": f"Rule error: {str(e)[:100]}"
            })
    return results


def audit_file(sol_path):
    if not os.path.exists(sol_path):
        return {"error": f"File not found: {sol_path}"}

    with open(sol_path, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    t0 = time.time()
    results = run_all_rules(code, os.path.basename(sol_path))

    total = sum(r.get("score", 0) for r in results)
    max_possible = sum(r["max_score"] for r in results)
    pct = round(total / max_possible * 100) if max_possible > 0 else 0
    grade = "A" if pct >= 90 else ("B" if pct >= 70 else ("C" if pct >= 50 else "D"))

    failures = [r for r in results if not r.get("pass")]
    critical = [r for r in failures if r["severity"] == "critical"]
    high = [r for r in failures if r["severity"] == "high"]

    return {
        "file": sol_path,
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "score": {"total": total, "max": max_possible, "pct": pct, "grade": grade},
        "findings": {
            "total": len(failures),
            "critical": len(critical),
            "high": len(high),
            "details": [{
                "rule_id": r["rule_id"], "rule_name": r["rule_name"],
                "severity": r["severity"], "detail": r["detail"],
                "line": r.get("line")
            } for r in failures]
        },
        "meta": {"elapsed_s": round(time.time() - t0, 1), "file_size": len(code)},
    }


def audit_directory(dir_path):
    reports = []
    for root, _, files in os.walk(dir_path):
        if ".git" in root or "node_modules" in root:
            continue
        for f in files:
            if f.endswith(".sol"):
                report = audit_file(os.path.join(root, f))
                reports.append(report)
    return reports


def audit_repo(repo_url):
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp(prefix="sol-")
    try:
        clone_url = repo_url if repo_url.startswith("http") else f"https://github.com/{repo_url}.git"
        r = subprocess.run(["git", "clone", "--depth", "1", clone_url, tmpdir],
                          capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return [{"error": f"Clone failed: {r.stderr[:200]}"}]
        return audit_directory(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Solidity Auditor — 25 rules")
    ap.add_argument("--path", help="Path to .sol file")
    ap.add_argument("--dir", help="Directory with .sol files")
    ap.add_argument("--repo", help="GitHub repo")
    ap.add_argument("--output", help="Output JSON path")
    args = ap.parse_args()

    if args.path:
        reports = [audit_file(args.path)]
    elif args.dir:
        reports = audit_directory(args.dir)
    elif args.repo:
        reports = audit_repo(args.repo)
    else:
        ap.print_help()
        sys.exit(1)

    output = {
        "auditor": "solidity-auditor v0.1.0",
        "timestamp": datetime.now(TZ_CN).isoformat(),
        "reports": reports,
    }

    outpath = args.output or "audit_report.json"
    with open(outpath, "w") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    # Summary
    for rep in reports:
        if "score" in rep:
            s = rep["score"]; f = rep["findings"]
            print(f"  {os.path.basename(rep['file']):40s} {s['pct']:3d}/100 {s['grade']} "
                  f"⚠{f['total']}(↯{f['critical']} ↑{f['high']})", file=sys.stderr)

    print(f"\nReport: {outpath}", file=sys.stderr)


if __name__ == "__main__":
    main()
