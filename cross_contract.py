#!/usr/bin/env python3
"""
Cross-Contract Call Chain Analyzer
追踪跨合约调用，检测 Oracle 依赖、权限链、闪贷攻击路径
"""
import os, re, json
from collections import defaultdict


def analyze_project(project_dir: str) -> dict:
    """Analyze all .sol files in a project for cross-contract vulnerabilities"""
    
    # Step 1: Find all .sol files and their imports
    files = {}
    imports = defaultdict(set)  # file -> imported files
    contracts = {}  # file -> [contract names]
    external_calls = defaultdict(list)  # file -> [(contract, func, line)]
    
    for root, _, filenames in os.walk(project_dir):
        if ".git" in root or "node_modules" in root:
            continue
        for f in filenames:
            if not f.endswith(".sol"):
                continue
            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
            except:
                continue
            
            rel = os.path.relpath(path, project_dir)
            files[rel] = code
            
            # Extract imports
            for m in re.finditer(r'import\s+["\'](.+?)["\']', code):
                imported = m.group(1)
                if not imported.startswith("http") and not imported.startswith("@"):
                    imports[rel].add(imported)
            
            # Extract contract names
            for m in re.finditer(r'(?:contract|interface|library)\s+(\w+)', code):
                contracts[rel] = contracts.get(rel, []) + [m.group(1)]
            
            # Extract external contract calls: variable.function() or Type(var).function()
            for m in re.finditer(r'(\w+)\s*\.\s*(\w+)\s*\(', code):
                contract_var = m.group(1)
                func = m.group(2)
                line = code[:m.start()].count('\n') + 1
                
                # Skip built-in Solidity patterns
                if contract_var in ('msg', 'tx', 'block', 'abi', 'this', 'super', 'type', 'keccak256', 'require', 'revert', 'assert', 'emit', 'new', 'return', 'if', 'for', 'while'):
                    continue
                if func in ('push', 'pop', 'length', 'send', 'transfer', 'call', 'delegatecall'):
                    continue
                
                # Try to resolve contract type from variable declaration
                contract_type = _resolve_type(code, contract_var)
                if contract_type:
                    external_calls[rel].append({
                        "contract": contract_type,
                        "function": func,
                        "line": line,
                        "variable": contract_var,
                    })
    
    # Step 2: Build call graph
    call_graph = defaultdict(set)
    for file, calls in external_calls.items():
        for call in calls:
            call_graph[file].add(call["contract"])
    
    # Step 3: Detect dangerous patterns
    findings = []
    
    # Pattern 1: Oracle dependency — contract depends on external price feed
    findings += _detect_oracle_dependency(files, external_calls, call_graph)
    
    # Pattern 2: Cross-contract reentrancy — A calls B which calls back to A
    findings += _detect_cross_reentrancy(files, external_calls, call_graph)
    
    # Pattern 3: Flash loan call chain — uncollateralized borrow + swap
    findings += _detect_flashloan_chain(files, external_calls)
    
    # Pattern 4: Authorization bypass across contracts
    findings += _detect_cross_contract_auth(files, external_calls)
    
    return {
        "files": len(files),
        "contracts": sum(len(c) for c in contracts.values()),
        "external_calls": sum(len(c) for c in external_calls.values()),
        "imports": sum(len(i) for i in imports.values()),
        "call_graph": {k: list(v) for k, v in call_graph.items()},
        "findings": findings,
    }


def _resolve_type(code: str, var_name: str) -> str | None:
    """Resolve contract variable type from declaration"""
    # Pattern: ContractType public varName;
    # Pattern: IContractType public varName;
    patterns = [
        rf'(?:contract|interface)\s+(\w+)\s+.*?\b{var_name}\b',
        rf'(\w+)\s+(?:public|private|internal|immutable)\s+{var_name}\s*[;=]',
        rf'I(\w+)\s+(?:public|private|internal|immutable)\s+{var_name}\s*[;=]',
    ]
    for pat in patterns:
        m = re.search(pat, code)
        if m:
            return m.group(1)
    return None


def _detect_oracle_dependency(files, external_calls, call_graph) -> list:
    """Detect contracts that depend on external oracle/price feeds"""
    findings = []
    oracle_funcs = ['getPrice', 'getReserves', 'latestRoundData', 'get_virtual_price',
                    'consult', 'getAmountOut', 'getAmountsOut']
    
    for file, calls in external_calls.items():
        for call in calls:
            if any(of in call["function"] for of in oracle_funcs):
                # Check if this oracle call affects critical operations
                code = files.get(file, "")
                has_critical = bool(re.search(r'(?:mint|burn|liquidate|borrow|swap|withdraw)', code))
                if has_critical:
                    findings.append({
                        "type": "oracle_dependency",
                        "severity": "critical",
                        "file": file,
                        "detail": f"关键操作依赖 {call['contract']}.{call['function']}() — Oracle 操纵风险",
                        "line": call["line"],
                    })
    return findings


def _detect_cross_reentrancy(files, external_calls, call_graph) -> list:
    """Detect potential cross-contract reentrancy (A→B→A)"""
    findings = []
    
    for file_a, calls_a in external_calls.items():
        for file_b, calls_b in external_calls.items():
            if file_a == file_b:
                continue
            # Check if A calls B and B could call back to A
            a_calls_b = any(c["contract"] in file_b for c in calls_a)
            b_calls_a = any(c["contract"] in file_a for c in calls_b)
            if a_calls_b and b_calls_a:
                findings.append({
                    "type": "cross_reentrancy",
                    "severity": "critical",
                    "file": file_a,
                    "detail": f"跨合约重入风险: {os.path.basename(file_a)} ↔ {os.path.basename(file_b)}",
                })
    return findings


def _detect_flashloan_chain(files, external_calls) -> list:
    """Detect flash loan paths: borrow → swap → manipulate → repay"""
    findings = []
    flash_found = False
    swap_found = False
    
    for file, calls in external_calls.items():
        for call in calls:
            if call["function"] in ('flashLoan', 'flashloan', 'borrow'):
                flash_found = True
            if call["function"] in ('swap', 'exchange'):
                swap_found = True
    
    if flash_found and swap_found:
        findings.append({
            "type": "flashloan_chain",
            "severity": "high",
            "file": "multiple",
            "detail": "闪贷 + swap 跨合约调用链 — 价格操纵攻击路径",
        })
    return findings


def _detect_cross_contract_auth(files, external_calls) -> list:
    """Detect authorization bypass across contract boundaries"""
    findings = []
    
    for file, calls in external_calls.items():
        code = files.get(file, "")
        has_own_auth = bool(re.search(r'(?:onlyOwner|require\(msg\.sender|AccessControl)', code))
        
        for call in calls:
            if call["function"] in ('transferOwnership', 'setAdmin', 'upgradeTo', 'mint', 'pause'):
                if not has_own_auth:
                    findings.append({
                        "type": "cross_contract_auth_bypass",
                        "severity": "high",
                        "file": file,
                        "detail": f"调用 {call['contract']}.{call['function']}() 无本地权限检查",
                        "line": call["line"],
                    })
    return findings


if __name__ == "__main__":
    import sys
    result = analyze_project(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(result, ensure_ascii=False, indent=2))
