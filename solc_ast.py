#!/usr/bin/env python3
"""
Solc AST Compiler — 编译 Solidity 为结构化 AST
支持: 函数调用图、状态变量追踪、存储读写分析
"""
import json
import os
import subprocess
import tempfile
from collections import defaultdict


def compile_ast(filepath: str) -> dict:
    """Compile a .sol file to AST JSON"""
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    tmp = tempfile.mktemp(suffix=".json")
    try:
        r = subprocess.run(
            ["solc", "--ast-compact-json", filepath, "-o", os.path.dirname(tmp)],
            capture_output=True, text=True, timeout=30
        )
        # solc outputs to file, find it
        base = os.path.splitext(os.path.basename(filepath))[0]
        ast_path = os.path.join(os.path.dirname(tmp), f"{base}.json")
        # Or try standard output path
        possible = [ast_path,
                    os.path.join(os.path.dirname(tmp), filepath.replace("/","_").replace("\\","_") + ".json")]
        for p in possible:
            if os.path.exists(p):
                with open(p) as f:
                    return json.load(f)
        # Fallback: parse from stdout
        if "nodeType" in r.stdout[:50]:
            return json.loads(r.stdout)
        return {"error": "No AST output", "stderr": r.stderr[:300]}
    except Exception as e:
        return {"error": str(e)[:200]}


def extract_functions(ast_node: dict, depth: int = 0) -> list:
    """Recursively extract all FunctionDefinition nodes"""
    funcs = []
    if not isinstance(ast_node, dict):
        return funcs

    if ast_node.get("nodeType") == "FunctionDefinition":
        funcs.append(ast_node)

    for key in ("nodes", "body", "statements", "subNodes",
                "members", "overrides", "modifiers", "parameters",
                "returnParameters", "expression", "initialValue",
                "functionSelector", "baseContracts"):
        val = ast_node.get(key)
        if isinstance(val, list):
            for item in val:
                funcs.extend(extract_functions(item, depth+1))
        elif isinstance(val, dict):
            funcs.extend(extract_functions(val, depth+1))

    return funcs


def extract_state_variables(ast_node: dict) -> list:
    """Extract all state variable declarations"""
    vars_ = []
    if not isinstance(ast_node, dict):
        return vars_

    if ast_node.get("nodeType") == "VariableDeclaration" and ast_node.get("stateVariable"):
        vars_.append({
            "name": ast_node.get("name"),
            "type": ast_node.get("typeName", {}).get("name", "?"),
            "visibility": ast_node.get("visibility", "internal"),
            "constant": ast_node.get("constant", False),
            "immutable": ast_node.get("mutability") == "immutable",
            "initialValue": str(ast_node.get("value", ""))[:100],
        })

    for key in ("nodes", "members"):
        val = ast_node.get(key, [])
        if isinstance(val, list):
            for item in val:
                vars_.extend(extract_state_variables(item))

    return vars_


def extract_external_calls(ast_node: dict) -> list:
    """Extract all external function calls (.call, .transfer, etc.)"""
    calls = []

    def _walk(node, depth=0):
        if not isinstance(node, dict):
            return
        nt = node.get("nodeType", "")
        if nt == "FunctionCall":
            expr = node.get("expression", {})
            # Check for member access like .call, .transfer, .delegatecall
            if expr.get("nodeType") == "MemberAccess":
                member = expr.get("memberName", "")
                if member in ("call", "delegatecall", "staticcall", "transfer", "send"):
                    calls.append({
                        "type": member,
                        "arguments": len(node.get("arguments", [])),
                        "src": node.get("src", "?"),
                    })
            # Check for function calls to external contracts
            elif expr.get("nodeType") == "Identifier":
                name = expr.get("name", "")
                if name and name[0].isupper():  # Likely contract reference
                    calls.append({
                        "type": "external_call",
                        "target": name,
                        "arguments": len(node.get("arguments", [])),
                        "src": node.get("src", "?"),
                    })

        for key in ("nodes", "body", "statements", "expression",
                     "initialValue", "trueBody", "falseBody"):
            val = node.get(key)
            if isinstance(val, list):
                for item in val:
                    _walk(item, depth+1)
            elif isinstance(val, dict):
                _walk(val, depth+1)

    _walk(ast_node)
    return calls


def extract_assignments(ast_node: dict) -> list:
    """Extract all state variable assignments"""
    assignments = []

    def _walk(node, depth=0):
        if not isinstance(node, dict):
            return
        nt = node.get("nodeType", "")
        if nt == "Assignment":
            lhs = node.get("leftHandSide", {})
            if lhs.get("nodeType") == "MemberAccess":
                assignments.append({
                    "variable": lhs.get("memberName", "?"),
                    "operator": node.get("operator", "="),
                    "src": node.get("src", "?"),
                })
            elif lhs.get("referencedDeclaration"):
                assignments.append({
                    "variable": lhs.get("name", "?"),
                    "operator": node.get("operator", "="),
                    "src": node.get("src", "?"),
                })

        for key in ("nodes", "body", "statements", "expression",
                     "initialValue", "trueBody", "falseBody"):
            val = node.get(key)
            if isinstance(val, list):
                for item in val:
                    _walk(item, depth+1)
            elif isinstance(val, dict):
                _walk(val, depth+1)

    _walk(ast_node)
    return assignments


def analyze_contract(filepath: str) -> dict:
    """Full contract analysis: AST + functions + calls + variables"""
    ast = compile_ast(filepath)
    if "error" in ast:
        return ast

    functions = extract_functions(ast)
    state_vars = extract_state_variables(ast)
    external_calls = extract_external_calls(ast)
    assignments = extract_assignments(ast)

    # Build function summary
    func_summary = []
    for fn in functions:
        name = fn.get("name", "?")
        visibility = fn.get("visibility", "internal")
        modifiers = [m.get("modifierName", {}).get("name", "?")
                     for m in fn.get("modifiers", [])]
        parameters = [p.get("name", "?") for p in
                      fn.get("parameters", {}).get("parameters", [])]
        body_stmts = len(fn.get("body", {}).get("statements", []))

        func_summary.append({
            "name": name,
            "visibility": visibility,
            "modifiers": modifiers,
            "parameters": parameters[:5],
            "body_statement_count": body_stmts,
        })

    return {
        "file": filepath,
        "contracts": _extract_contract_names(ast),
        "functions": func_summary,
        "function_count": len(functions),
        "state_variables": state_vars,
        "state_variable_count": len(state_vars),
        "external_calls": external_calls,
        "external_call_count": len(external_calls),
        "assignments": len(assignments),
    }


def _extract_contract_names(ast: dict) -> list:
    """Extract contract/library/interface names"""
    names = []

    def _walk(node):
        if not isinstance(node, dict):
            return
        if node.get("nodeType") == "ContractDefinition":
            names.append({
                "name": node.get("name", "?"),
                "kind": node.get("contractKind", "contract"),
                "baseContracts": [b.get("baseName", {}).get("name", "?")
                                  for b in node.get("baseContracts", [])],
            })
        for key in ("nodes", "members"):
            val = node.get(key, [])
            if isinstance(val, list):
                for item in val:
                    _walk(item)

    _walk(ast)
    return names


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python solc_ast.py <file.sol>")
        sys.exit(1)

    result = analyze_contract(sys.argv[1])
    print(json.dumps(result, ensure_ascii=False, indent=2))
