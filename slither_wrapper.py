#!/usr/bin/env python3
"""
Slither Integration — 70+ professional detectors
Wraps slither CLI, parses JSON output, converts to Solidty Auditor format.
"""
import json
import os
import re
import subprocess
import tempfile


def run_slither(target_path: str, timeout: int = 120) -> dict:
    """
    Run slither on a .sol file or directory.
    Returns parsed findings or None on failure.
    """
    if not os.path.exists(target_path):
        return {"error": f"Path not found: {target_path}"}

    cmd = ["slither", target_path, "--json", "/tmp/slither_output.json"]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout,
            cwd=os.path.dirname(target_path) if os.path.isfile(target_path) else target_path
        )
        json_path = "/tmp/slither_output.json"
        if not os.path.exists(json_path):
            # Try alternate location
            json_path = os.path.join(tempfile.gettempdir(), "slither_output.json")
            if not os.path.exists(json_path):
                return {"error": "Slither produced no output file", "stderr": r.stderr[:500]}

        with open(json_path, "r") as f:
            data = json.load(f)

        return parse_slither_output(data)

    except subprocess.TimeoutExpired:
        return {"error": "Slither timed out"}
    except json.JSONDecodeError as e:
        return {"error": f"Slither output parse error: {e}"}
    except Exception as e:
        return {"error": str(e)[:200]}


def parse_slither_output(data: dict) -> dict:
    """Convert Slither JSON to our audit format"""
    results = data.get("results", {})
    detectors = results.get("detectors", [])

    findings = []
    critical = high = medium = low = info = 0
    rule_id = 100  # Start at 100 to avoid collision with our rules

    for detector in detectors:
        check_name = detector.get("check", "unknown")
        description = detector.get("description", "")
        impact = detector.get("impact", "Informational")
        confidence = detector.get("confidence", "Medium")

        # Map to our severity
        sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "low"}
        severity = sev_map.get(impact, "low")

        # Count by severity
        elements = detector.get("elements", [])
        count = len(elements) if elements else 1
        if impact == "High": high += count
        elif impact == "Medium": medium += count
        elif impact == "Low": low += count
        else: info += count

        # Extract source locations
        locations = []
        for el in elements[:5]:  # Limit to 5 per detector
            sm = el.get("source_mapping", {})
            loc = {
                "file": sm.get("filename_relative", "?"),
                "line": sm.get("lines", [0])[0] if sm.get("lines") else 0,
                "contract": el.get("contract", "?"),
                "function": el.get("function_name", "?")
            }
            locations.append(loc)

        findings.append({
            "rule_id": rule_id,
            "rule_name": check_name,
            "category": "security",
            "severity": severity,
            "source": "slither",
            "detail": description[:300],
            "count": count,
            "locations": locations,
        })
        rule_id += 1

    return {
        "source": "slither",
        "summary": {
            "total_detectors": len(detectors),
            "total_findings": len(findings),
            "high": high, "medium": medium, "low": low, "info": info,
        },
        "findings": findings,
    }


def run_slither_on_dir(dir_path: str) -> dict:
    """Run Slither on all .sol files in a directory"""
    all_findings = []
    total_high = total_med = total_low = 0

    for root, _, files in os.walk(dir_path):
        if ".git" in root or "node_modules" in root:
            continue
        for f in files:
            if f.endswith(".sol"):
                filepath = os.path.join(root, f)
                print(f"  Slither: {os.path.relpath(filepath, dir_path)} ...", file=__import__('sys').stderr, end=" ")
                result = run_slither(filepath, timeout=60)
                if "error" in result:
                    print(f"✗ {result['error'][:60]}", file=__import__('sys').stderr)
                else:
                    summary = result.get("summary", {})
                    print(f"✓ {summary.get('total_findings', 0)} findings (H:{summary.get('high',0)} M:{summary.get('medium',0)})",
                          file=__import__('sys').stderr)
                    for finding in result.get("findings", []):
                        finding["file"] = filepath
                        all_findings.append(finding)
                    total_high += summary.get("high", 0)
                    total_med += summary.get("medium", 0)
                    total_low += summary.get("low", 0)

    return {
        "source": "slither",
        "summary": {
            "total_findings": len(all_findings),
            "high": total_high, "medium": total_med, "low": total_low,
        },
        "findings": all_findings,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python slither_wrapper.py <file_or_dir>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isfile(target):
        result = run_slither(target)
    else:
        result = run_slither_on_dir(target)

    print(json.dumps(result, ensure_ascii=False, indent=2))
