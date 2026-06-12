#!/usr/bin/env python3
"""
Solidity Auditor — DeFi 专项规则 (26-50)
闪电贷、MEV、价格操纵、治理攻击、跨链桥、借贷、稳定币、签名、代理升级
"""
import re

DEFI_RULES = []

def defi_rule(id, name, severity="high", score=4):
    def decorator(fn):
        DEFI_RULES.append({
            "id": id, "name": name, "severity": severity, "max_score": score,
            "check": fn, "category": "defi"
        })
        return fn
    return decorator


@defi_rule(26, "flashloan-atomic-arbitrage", "high")
def rule_26(code, filename, ctx):
    has_loan = bool(re.search(r'(?:flashLoan|flashloan|borrow\s*\(.*amount)', code, re.IGNORECASE))
    has_swap = bool(re.search(r'(?:swap|exchange)\s*\(', code, re.IGNORECASE))
    if has_loan and has_swap:
        return {"pass": False, "score": 0, "detail": "闪电贷+swap同存 — 价格操纵攻击路径"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(27, "mev-sandwich-no-slippage", "critical")
def rule_27(code, filename, ctx):
    amm_funcs = re.findall(r'function\s+(swap|exchange|trade)\w*\s*\(', code, re.IGNORECASE)
    if amm_funcs:
        if not any(kw in code for kw in ['amountOutMin','minReturn','minAmountOut','sqrtPriceLimitX96']):
            return {"pass": False, "score": 0, "detail": f"AMM 函数缺滑点保护 — 三明治攻击"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(28, "governance-timelock-missing", "critical")
def rule_28(code, filename, ctx):
    for func in ['execute','propose','queue','setFee','setAdmin']:
        if re.search(rf'function\s+{func}\s*\(', code):
            if 'timelock' not in code.lower() and 'delay' not in code.lower():
                return {"pass": False, "score": 0, "detail": f"治理函数 {func}() 缺时间锁"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(29, "governance-flashloan-vote", "high")
def rule_29(code, filename, ctx):
    if re.search(r'(?:vote|governor|propose)', code, re.IGNORECASE):
        if 'getPastVotes' in code or 'getVotes' in code:
            if 'snapshot' not in code.lower():
                return {"pass": False, "score": 0, "detail": "投票快照缺失 — 闪电贷投票攻击"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(30, "bridge-replay-attack", "critical")
def rule_30(code, filename, ctx):
    if re.search(r'(?:sendMessage|relayMessage|_sendPacket)', code):
        if 'chainId' not in code and 'block.chainid' not in code:
            return {"pass": False, "score": 0, "detail": "跨链缺chainId — 重放攻击"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(31, "bridge-infinite-mint", "critical")
def rule_31(code, filename, ctx):
    if re.search(r'function\s+mint\s*\(', code):
        if re.search(r'(?:bridge|lzSend|OFT|layerZero)', code, re.IGNORECASE):
            if 'cap' not in code.lower():
                return {"pass": False, "score": 0, "detail": "跨链铸币缺总量限制"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(32, "lending-oracle-stale", "high")
def rule_32(code, filename, ctx):
    has_lending = re.search(r'(?:borrow|lend|collateral|liquidation)', code, re.IGNORECASE)
    if has_lending and 'price' in code.lower():
        if 'stale' not in code.lower():
            return {"pass": False, "score": 0, "detail": "借贷Oracle缺过期检查"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(33, "lending-liquidation-incentive", "high")
def rule_33(code, filename, ctx):
    if re.search(r'function\s+liquidate\s*\(', code):
        if not any(kw in code.lower() for kw in ['bonus','incentive','discount']):
            return {"pass": False, "score": 1, "detail": "清算缺激励 — 坏账累积风险"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(34, "vault4626-inflation-attack", "high")
def rule_34(code, filename, ctx):
    if re.search(r'(?:ERC4626|maxDeposit|maxMint|previewDeposit)', code):
        if not any(kw in code for kw in ['deadShares','MINIMUM_SHARES','decimalsOffset']):
            return {"pass": False, "score": 0, "detail": "ERC-4626缺通胀攻击防护"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(35, "vault4626-view-revert", "medium")
def rule_35(code, filename, ctx):
    if re.search(r'function\s+maxDeposit\s*\(', code):
        if 'paused()' in code and 'try' not in code:
            return {"pass": False, "score": 2, "detail": "maxDeposit暂停时可能revert"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(36, "staking-reward-drain", "critical")
def rule_36(code, filename, ctx):
    has_stake = bool(re.search(r'(?:stake|deposit).*\(', code))
    has_reward = bool(re.search(r'(?:getReward|claimReward|harvest)\s*\(', code))
    if has_stake and has_reward:
        if 'lock' not in code.lower() and 'vesting' not in code.lower():
            return {"pass": False, "score": 0, "detail": "奖励可立即领取 — Flash-stake攻击"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(37, "staking-early-exit", "medium")
def rule_37(code, filename, ctx):
    if re.search(r'function\s+(?:unstake|withdraw)\s*\(', code):
        if not any(kw in code.lower() for kw in ['penalty','fee','lock']):
            return {"pass": False, "score": 2, "detail": "质押退出无锁定期/惩罚"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(38, "stablecoin-depeg-oracle", "high")
def rule_38(code, filename, ctx):
    has_stable = re.search(r'(?:stablecoin|stable\w*Coin|peg)', code, re.IGNORECASE)
    if has_stable and 'price' in code.lower():
        oracle_count = len(re.findall(r'(?:Chainlink|oracle|priceFeed|Aggregator)', code, re.IGNORECASE))
        if oracle_count <= 1:
            return {"pass": False, "score": 0, "detail": "稳定币单Oracle — 脱钩风险"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(39, "stablecoin-mint-cap", "high")
def rule_39(code, filename, ctx):
    if re.search(r'function\s+mint\s*\(', code):
        if re.search(r'(?:stable|USD|USDC)', code, re.IGNORECASE):
            if not any(kw in code.lower() for kw in ['cap','limit','maxSupply']):
                return {"pass": False, "score": 0, "detail": "稳定币铸币缺供应上限"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(40, "access-role-escalation", "high")
def rule_40(code, filename, ctx):
    if re.search(r'(?:grantRole|revokeRole|DEFAULT_ADMIN)', code):
        if 'timelock' not in code.lower() and 'multisig' not in code.lower():
            return {"pass": False, "score": 1, "detail": "权限授予无时间锁 — 单点作恶"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(41, "access-pauser-centralization", "medium")
def rule_41(code, filename, ctx):
    if re.search(r'(?:pause|unpause)\s*\(', code):
        if 'onlyOwner' in code:
            return {"pass": False, "score": 2, "detail": "暂停权限在owner — 单点风险"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(42, "dos-external-call-loop", "high")
def rule_42(code, filename, ctx):
    if re.search(r'for\s*\([^)]*\)[^{]*\{[^}]*\.(?:call|transfer|send|delegatecall)', code, re.DOTALL):
        return {"pass": False, "score": 0, "detail": "循环中外部调用 — Gas炸弹DoS"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(43, "dos-block-gas-limit", "medium")
def rule_43(code, filename, ctx):
    if re.search(r'for\s*\([^;]*;\s*\w+\.length', code):
        return {"pass": False, "score": 1, "detail": "遍历数组长度 — Gas耗尽DoS"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(44, "signature-deadline-missing", "high")
def rule_44(code, filename, ctx):
    if re.search(r'(?:permit|ecrecover|ECDSA\.recover)', code):
        if 'deadline' not in code.lower():
            return {"pass": False, "score": 0, "detail": "签名缺deadline — 永久有效"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(45, "signature-eip712-domain", "medium")
def rule_45(code, filename, ctx):
    if 'permit(' in code and '_PERMIT_TYPEHASH' in code:
        if 'DOMAIN_SEPARATOR' not in code:
            return {"pass": False, "score": 2, "detail": "缺DOMAIN_SEPARATOR — 跨合约重放"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(46, "defi-emergency-pause-missing", "high")
def rule_46(code, filename, ctx):
    if re.search(r'(?:totalValueLocked|totalSupply|mint|swap|deposit)', code):
        if 'pause' not in code.lower():
            return {"pass": False, "score": 0, "detail": "大额资产合约缺暂停机制"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(47, "defi-upgrade-proxy-storage", "critical")
def rule_47(code, filename, ctx):
    if re.search(r'(?:delegatecall|fallback\(\)|_implementation)', code):
        if not any(g in code for g in ['storageGap','__gap','reserved']):
            return {"pass": False, "score": 0, "detail": "代理合约缺storage gap — 升级冲突"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(48, "defi-initializer-race", "high")
def rule_48(code, filename, ctx):
    if re.search(r'function\s+(?:init|initialize|setup)\s*\(', code):
        if 'initializer' not in code and 'onlyOwner' not in code:
            return {"pass": False, "score": 0, "detail": "初始化可被抢跑"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(49, "defi-fee-on-transfer", "medium")
def rule_49(code, filename, ctx):
    if re.search(r'(?:transfer|transferFrom|safeTransfer)\s*\(', code):
        if 'balanceBefore' not in code and 'balanceAfter' not in code:
            if 'USDT' in code or 'fee' in code.lower():
                return {"pass": False, "score": 2, "detail": "转账缺before/after余额差 — fee-on-token问题"}
    return {"pass": True, "score": 4, "detail": "OK"}

@defi_rule(50, "defi-rebase-token-incompat", "high")
def rule_50(code, filename, ctx):
    if re.search(r'(?:balanceOf|totalSupply)', code):
        if 'rebasing' in code.lower():
            return {"pass": False, "score": 0, "detail": "协议假设余额不变 — rebase token不兼容"}
    return {"pass": True, "score": 4, "detail": "OK"}
