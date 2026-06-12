#!/usr/bin/env python3
"""
Security Ownership Mapper — 对标 Codex security-ownership-map skill
标注代码作者、审计历史、已知漏洞归属
"""
import json
import os
import subprocess
import re


def map_ownership(repo_path: str) -> dict:
    """
    git blame analysis: identify who wrote high-risk code
    Returns ownership map with risk zones
    """
    result = {"files": {}, "risk_zones": [], "summary": {}}

    # Find all .sol files
    sol_files = []
    for root, _, files in os.walk(repo_path):
        if ".git" in root: continue
        for f in files:
            if f.endswith(".sol"):
                sol_files.append(os.path.join(root, f))

    for sol_file in sol_files[:50]:  # Limit to 50 files
        rel = os.path.relpath(sol_file, repo_path)

        # git blame
        try:
            r = subprocess.run(
                ["git", "-C", repo_path, "blame", "--line-porcelain", sol_file],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0: continue

            authors = {}
            for line in r.stdout.split("\n"):
                if line.startswith("author "):
                    author = line[7:].strip()
                    authors[author] = authors.get(author, 0) + 1
                elif line.startswith("author-mail "):
                    pass

            total_lines = sum(authors.values())
            main_author = max(authors, key=authors.get) if authors else "unknown"

            result["files"][rel] = {
                "lines": total_lines,
                "main_author": main_author,
                "contributors": len(authors),
                "author_split": dict(sorted(authors.items(), key=lambda x: -x[1])[:3]),
            }

        except Exception:
            continue

    # Identify risk zones — files with high-risk patterns owned by single author
    risk_patterns = {
        "selfdestruct": r'selfdestruct|suicide',
        "delegatecall": r'delegatecall',
        "tx.origin": r'tx\.origin',
        "unchecked": r'unchecked\s*\{',
        "assembly": r'assembly\s*\{',
    }

    for pattern_name, pattern in risk_patterns.items():
        for sol_file in sol_files[:50]:
            try:
                with open(sol_file, "r") as f:
                    if re.search(pattern, f.read()):
                        rel = os.path.relpath(sol_file, repo_path)
                        if rel in result["files"]:
                            result["risk_zones"].append({
                                "file": rel,
                                "risk": pattern_name,
                                "owner": result["files"][rel]["main_author"],
                            })
            except: pass

    # Summary
    all_authors = {}
    for fi in result["files"].values():
        for author, lines in fi.get("author_split", {}).items():
            all_authors[author] = all_authors.get(author, 0) + lines

    result["summary"] = {
        "total_files": len(result["files"]),
        "total_risk_zones": len(result["risk_zones"]),
        "top_authors": dict(sorted(all_authors.items(), key=lambda x: -x[1])[:5]),
        "bus_factor": _calculate_bus_factor(all_authors),
    }

    return result


def _calculate_bus_factor(authors: dict) -> int:
    """How many authors need to leave before 50% of code has no owner?"""
    total = sum(authors.values())
    cumulative = 0
    for i, (_, lines) in enumerate(sorted(authors.items(), key=lambda x: -x[1])):
        cumulative += lines
        if cumulative > total * 0.5:
            return i + 1
    return len(authors)
