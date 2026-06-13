#!/usr/bin/env python3
"""Foundry/Hardhat project adapter — auto-detect project type and run audit"""
import os, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def detect_project_type(project_dir: str) -> str:
    """Detect if this is a Foundry, Hardhat, or standard Solidity project"""
    if os.path.exists(os.path.join(project_dir, "foundry.toml")):
        return "foundry"
    if os.path.exists(os.path.join(project_dir, "hardhat.config.js")) or \
       os.path.exists(os.path.join(project_dir, "hardhat.config.ts")):
        return "hardhat"
    return "standard"

def find_sol_files(project_dir: str, project_type: str) -> list:
    """Find .sol files based on project type"""
    search_dirs = {
        "foundry": ["src", "lib", "test"],
        "hardhat": ["contracts", "test"],
        "standard": ["contracts", "src", "."],
    }
    
    sol_files = []
    for search_dir in search_dirs.get(project_type, ["."]):
        full_dir = os.path.join(project_dir, search_dir)
        if not os.path.exists(full_dir):
            continue
        for root, _, files in os.walk(full_dir):
            if "node_modules" in root or ".git" in root or "lib/forge-std" in root:
                continue
            for f in files:
                if f.endswith(".sol") and not f.startswith("."):
                    sol_files.append(os.path.join(root, f))
    return sol_files


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Solidity Auditor — Foundry/Hardhat adapter")
    ap.add_argument("--dir", default=".")
    ap.add_argument("--output", default="audit_report.json")
    args = ap.parse_args()

    project_type = detect_project_type(args.dir)
    sol_files = find_sol_files(args.dir, project_type)

    print(f"Project: {project_type} | .sol files: {len(sol_files)}")

    from auditor_v3 import full_audit
    reports = [full_audit(sf) for sf in sol_files[:100]]  # Limit

    total = sum(r["findings"]["total"] for r in reports)
    crit = sum(r["findings"]["critical"] for r in reports)

    output = {
        "auditor": "solidity-auditor v4",
        "project_type": project_type,
        "summary": {"files": len(reports), "total_findings": total, "critical": crit},
        "reports": reports,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"Report: {args.output} | {total} findings ({crit} crit)")
