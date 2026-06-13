#!/usr/bin/env python3
"""
Solidity Auditor — 25 Security Rules
对标 Hermes Skill Auditor，面向 Solidity 智能合约安全审计

规则来源: OWASP Smart Contract Top 10, SWC Registry, 实战经验
"""
import re

RULES = []

def rule(id, name, severity="medium", score=4):
    """severity: critical/high/medium/low"""
    def decorator(fn):
        RULES.append({
            "id": id, "name": name, "severity": severity, "max_score": score,
            "check": fn, "category": "security"
        })
        return fn
    return decorator


# ═══════════════════════════════════════════
#  重入攻击 (SWC-107)
# ═══════════════════════════════════════════

@rule(1, "reentrancy-external-call", "critical")
def rule_01(code, filename, ctx):
    """外部调用后修改状态——经典重入漏洞"""
    # Pattern: .call{value: ...}("") AFTER state change is safe
    # Pattern: .call{value: ...}("") BEFORE state change = vulnerable
    has_external_call = bool(re.search(r'\.call\{value:', code))
    # Check if state change happens after the call
    if has_external_call:
        # Look for state writes after .call
        matches = list(re.finditer(r'\.call\{value:.*?\}\([^)]*\)', code))
        for m in matches:
            after = code[m.end():m.end()+500]
            assignments = re.findall(r'(\w+\s*[+\-*/]?=\s*[^=])|(mapping\(.*?\).*?=\s*)|(\.push\()', after)
            if not assignments:
                return {"pass": False, "score": 0,
                        "detail": f"外部调用后缺少状态更新 — 重入攻击风险 (SWC-107)",
                        "line": code[:m.start()].count('\n') + 1}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(2, "reentrancy-no-cei", "critical")
def rule_02(code, filename, ctx):
    """检查是否符合 CEI 模式 (Checks-Effects-Interactions)"""
    external_calls = re.findall(r'(\.call\{|\.transfer\(|\.send\()', code)
    if external_calls:
        for call_match in re.finditer(r'(\.call\{|\.transfer\(|\.send\()', code):
            before_call = code[:call_match.start()][-300:]
            if 'require(' not in before_call and 'if (' not in before_call:
                return {"pass": False, "score": 0,
                        "detail": "缺少 CEI 模式 — 外部调用前缺少校验 (require/if)",
                        "line": code[:call_match.start()].count('\n') + 1}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(3, "reentrancy-unchecked-send", "high")
def rule_03(code, filename, ctx):
    """未检查 .send() / .call() 返回值"""
    sends = re.findall(r'(\.send\([^)]*\))(?!.*require)', code)
    calls = re.findall(r'(\.call\{[^}]*\}\([^)]*\))\s*(?!.*=.*require)', code)
    if sends or calls:
        return {"pass": False, "score": 0,
                "detail": f"未检查 .send/.call 返回值 ({len(sends)} send, {len(calls)} call)",
                "findings": sends[:2] + calls[:2]}
    return {"pass": True, "score": 4, "detail": "OK"}


# ═══════════════════════════════════════════
#  权限控制 (SWC-106)
# ═══════════════════════════════════════════

@rule(4, "access-missing-owner-check", "high")
def rule_04(code, filename, ctx):
    """关键函数缺少 onlyOwner 修饰符"""
    critical_funcs = ['withdraw', 'transferOwnership', 'setFee', 'mint',
                      'burn', 'pause', 'unpause', 'upgradeTo', 'setAdmin']
    findings = []
    for func in critical_funcs:
        pattern = rf'function\s+{func}\s*\([^)]*\)[^{{]*\{{'
        if re.search(pattern, code, re.IGNORECASE):
            # Check if the function has onlyOwner or similar modifier
            func_match = re.search(pattern, code, re.IGNORECASE)
            func_start = func_match.start()
            func_body = code[func_start:func_start+200]
            if 'onlyOwner' not in func_body and 'require(msg.sender' not in func_body:
                findings.append(func)
    if findings:
        return {"pass": False, "score": 0,
                "detail": f"关键函数缺少权限检查: {', '.join(findings)}"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(5, "access-txorigin-auth", "high")
def rule_05(code, filename, ctx):
    """使用 tx.origin 做权限验证 (SWC-115)"""
    if 'tx.origin' in code and 'require(' in code:
        pattern = r'require\s*\(\s*tx\.origin\s*=='
        if re.search(pattern, code):
            return {"pass": False, "score": 0,
                    "detail": "使用 tx.origin 做鉴权 — 钓鱼攻击风险 (SWC-115)"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(6, "access-unprotected-selfdestruct", "critical")
def rule_06(code, filename, ctx):
    """selfdestruct 无权限保护"""
    if 'selfdestruct' in code or 'suicide' in code:
        # Find the function containing selfdestruct
        funcs = re.findall(r'function\s+(\w+)\s*\([^)]*\)[^{]*\{[^}]*?(?:selfdestruct|suicide)', code)
        for func in funcs:
            func_block = re.search(rf'function\s+{func}[^}}]*?\}}', code)
            if func_block and 'onlyOwner' not in func_block.group():
                return {"pass": False, "score": 0,
                        "detail": f"selfdestruct 在 {func}() 中无权限保护"}
    return {"pass": True, "score": 4, "detail": "OK"}


# ═══════════════════════════════════════════
#  算术漏洞 (SWC-101)
# ═══════════════════════════════════════════

@rule(7, "arithmetic-unchecked-math", "medium")
def rule_07(code, filename, ctx):
    """使用 unchecked 块 — 可能溢出"""
    if 'unchecked {' in code:
        return {"pass": False, "score": 1,
                "detail": "使用了 unchecked 块 — 需人工确认是否有溢出风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(8, "arithmetic-division-before-multiply", "medium")
def rule_08(code, filename, ctx):
    """除法在乘法之前 — 精度损失"""
    pattern = r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)'
    matches = re.findall(pattern, code)
    if matches:
        return {"pass": False, "score": 1,
                "detail": f"除法先于乘法 — 精度损失风险 ({len(matches)} 处)"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(9, "arithmetic-unsafe-casting", "high")
def rule_09(code, filename, ctx):
    """不安全类型转换 + Solidity <0.8 溢出检测"""
    # Check pre-0.8 pragma
    m = re.search(r'pragma\s+solidity\s+[\^~]?\s*0\.([0-7])', code)
    if m and 'SafeMath' not in code:
        return {"pass": False, "score": 0,
                "detail": f"pragma ^0.{m.group(1)} 无 SafeMath — 整数溢出风险 (SWC-101)"}
    downcasts = re.findall(r'(?:uint256|int256)\(.*?(?:int\d+|uint(?!256)\d+)[^)]*\)', code)
    if downcasts:
        return {"pass": False, "score": 1,
                "detail": f"不安全类型转换 {len(downcasts)} 处 — 可能溢出"}
    return {"pass": True, "score": 4, "detail": "OK"}


# ═══════════════════════════════════════════
#  闪电贷 / 价格操纵 (SWC-120)
# ═══════════════════════════════════════════

@rule(10, "oracle-spot-price", "high")
def rule_10(code, filename, ctx):
    """使用 AMM 现货价格作为 Oracle — 闪电贷操纵风险"""
    patterns = [
        r'getReserves\s*\(', r'\.balanceOf\s*\(.*\).*price',
        r'amountOut\s*\(', r'getAmountsOut\s*\('
    ]
    for pat in patterns:
        if re.search(pat, code):
            return {"pass": False, "score": 0,
                    "detail": f"使用现货价格 — 闪电贷价格操纵风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(11, "oracle-no-timelock", "medium")
def rule_11(code, filename, ctx):
    """价格更新无时间锁"""
    has_price_update = bool(re.search(r'(?:setPrice|updatePrice|setOracle)\s*\(', code))
    if has_price_update:
        if 'block.timestamp' not in code or 'timeLock' not in code:
            return {"pass": False, "score": 2,
                    "detail": "价格更新函数无时间锁保护"}
    return {"pass": True, "score": 4, "detail": "OK"}


# ═══════════════════════════════════════════
#  存储 / 升级安全
# ═══════════════════════════════════════════

@rule(12, "storage-collision-upgrade", "critical")
def rule_12(code, filename, ctx):
    """可升级合约的存储冲突风险"""
    is_upgradeable = bool(re.search(r'(?:UUPS|Transparent|Beacon|upgradeable|initializer)', code, re.IGNORECASE))
    if is_upgradeable:
        # Check if storage gaps are present
        if '__gap' not in code and 'storageGap' not in code:
            return {"pass": False, "score": 0,
                    "detail": "可升级合约缺少 storage gap — 升级时存储冲突风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(13, "upgrade-initializer-unprotected", "critical")
def rule_13(code, filename, ctx):
    """initialize() 可被重复调用"""
    if re.search(r'function\s+initialize\s*\(', code):
        if 'initializer' not in code and 'initialized' not in code.lower():
            return {"pass": False, "score": 0,
                    "detail": "initialize() 无防重复调用保护"}
    return {"pass": True, "score": 4, "detail": "OK"}


# ═══════════════════════════════════════════
#  通用安全实践
# ═══════════════════════════════════════════

@rule(14, "best-practice-unlocked-pragma", "low")
def rule_14(code, filename, ctx):
    """pragma 未锁定版本"""
    if re.match(r'pragma\s+solidity\s+\^', code.split('\n')[0]):
        return {"pass": False, "score": 1,
                "detail": "pragma 使用 ^ 而非精确版本 — 部署行为不确定"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(15, "best-practice-zero-address-check", "medium")
def rule_15(code, filename, ctx):
    """构造函数/setter 缺少零地址检查"""
    findings = []
    # Check constructor params
    ctor = re.search(r'constructor\s*\(([^)]*)\)', code)
    if ctor:
        params = ctor.group(1).split(',')
        addr_params = [p.strip().split()[-1] for p in params if 'address' in p]
        if addr_params:
            body = code[ctor.end():ctor.end()+300]
            for ap in addr_params:
                if f'require({ap} != address(0))' not in body and \
                   f'{ap} != address(0)' not in body:
                    findings.append(ap)
    if findings:
        return {"pass": False, "score": 2,
                "detail": f"构造函数缺少零地址检查: {findings}"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(16, "best-practice-events-missing", "medium")
def rule_16(code, filename, ctx):
    """状态变更函数缺少事件"""
    state_changers = re.findall(r'function\s+(set\w+|update\w+|transfer|withdraw|deposit|mint|burn)\s*\(', code)
    no_events = []
    for func in set(state_changers):
        # Check if emit exists in the function body
        func_pattern = rf'function\s+{func}\s*\([^)]*\)[^{{]*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
        func_matches = re.findall(func_pattern, code, re.DOTALL)
        for body in func_matches:
            if 'emit ' not in body:
                no_events.append(func)
    if no_events:
        return {"pass": False, "score": 2,
                "detail": f"状态变更函数缺少事件: {', '.join(no_events[:5])}"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(17, "best-practice-delegatecall-untrusted", "critical")
def rule_17(code, filename, ctx):
    """delegatecall 到用户可控地址"""
    pattern = r'\.delegatecall\s*\(\s*(?!address\(this\))'
    if re.search(pattern, code):
        # Check if the target comes from user input
        return {"pass": False, "score": 0,
                "detail": "delegatecall 目标可能用户可控 — 代码执行风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(18, "best-practice-block-timestamp", "low")
def rule_18(code, filename, ctx):
    """block.timestamp 用于关键逻辑"""
    if 'block.timestamp' in code:
        critical_contexts = ['require(', 'if (', 'while (', '= block.timestamp']
        for ctx_pattern in critical_contexts:
            if f'{ctx_pattern} block.timestamp' in code or f'block.timestamp {ctx_pattern}' in code:
                return {"pass": False, "score": 2,
                        "detail": "block.timestamp 用于关键逻辑 — 矿工可操纵 (±15s)"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(19, "best-practice-weak-randomness", "high")
def rule_19(code, filename, ctx):
    """弱随机数 — 可被矿工/MEV 操纵"""
    rand_patterns = [
        r'block\.difficulty', r'blockhash\s*\(', r'block\.timestamp.*%',
        r'keccak256\(abi\.encodePacked\(.*block\.'
    ]
    for pat in rand_patterns:
        if re.search(pat, code):
            return {"pass": False, "score": 0,
                    "detail": f"使用链上可预测随机源 — 可被矿工操纵"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(20, "best-practice-erc20-approve-race", "high")
def rule_20(code, filename, ctx):
    """ERC20 approve 竞态条件"""
    if 'approve(' in code:
        # Check for increaseAllowance/decreaseAllowance
        if 'increaseAllowance' not in code and 'decreaseAllowance' not in code:
            # Check if approve is used with non-zero
            approve_lines = [l.strip() for l in code.split('\n') if 'approve(' in l]
            if approve_lines:
                return {"pass": False, "score": 2,
                        "detail": "使用 approve() 而非 increaseAllowance — 竞态条件风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(21, "best-practice-slippage-none", "high")
def rule_21(code, filename, ctx):
    """交易无滑点保护"""
    swap_funcs = re.findall(r'function\s+(swap|exchange|trade)\w*\s*\(', code)
    if swap_funcs:
        if 'amountOutMin' not in code and 'minReturn' not in code and \
           'minAmountOut' not in code:
            return {"pass": False, "score": 0,
                    "detail": "swap 函数缺少滑点保护 — 三明治攻击风险"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(22, "best-practice-flashloan-unprotected", "high")
def rule_22(code, filename, ctx):
    """闪电贷回调无防护"""
    has_callback = bool(re.search(r'(?:onFlashLoan|executeOperation|onNFTPurchase)', code))
    if has_callback:
        if 'onlyOwner' not in code and 'msg.sender == address(this)' not in code:
            return {"pass": False, "score": 0,
                    "detail": "闪电贷回调函数无权限检查"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(23, "best-practice-gas-griefing", "medium")
def rule_23(code, filename, ctx):
    """遍历无界数组 — Gas 耗尽 DoS"""
    for_loops = re.findall(r'for\s*\([^;]*;\s*(\w+)\.length', code)
    if for_loops:
        return {"pass": False, "score": 2,
                "detail": f"遍历 .length 数组 — 可能 Gas 耗尽 ({len(for_loops)} 处)"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(24, "best-practice-immutable-upgrade", "medium")
def rule_24(code, filename, ctx):
    """可升级合约中使用 immutable"""
    is_upgradeable = bool(re.search(r'(?:UUPS|upgradeable|initializer)', code, re.IGNORECASE))
    if is_upgradeable and 'immutable ' in code:
        return {"pass": False, "score": 2,
                "detail": "可升级合约使用 immutable — 升级后值不可变"}
    return {"pass": True, "score": 4, "detail": "OK"}


@rule(25, "best-practice-signature-replay", "high")
def rule_25(code, filename, ctx):
    """签名验证无防重放"""
    has_sig_check = bool(re.search(r'(?:ecrecover|ECDSA\.recover|SignatureChecker)', code))
    if has_sig_check:
        if 'nonce' not in code.lower() and 'deadline' not in code.lower():
            return {"pass": False, "score": 0,
                    "detail": "签名验证缺少 nonce/deadline — 重放攻击风险"}
    return {"pass": True, "score": 4, "detail": "OK"}
