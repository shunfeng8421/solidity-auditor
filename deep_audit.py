#!/usr/bin/env python3
"""
Deep CEI Checker + Vulnerability Signature Database (50+ patterns)

CEI = Checks-Effects-Interactions
The #1 cause of reentrancy: state changes AFTER external calls.

Signature DB: Known vulnerability patterns from real exploits.
"""
import re
import json

# ═══════════════════════════════════════════
#  CEI Deep Checker
# ═══════════════════════════════════════════

def check_cei_pattern(code: str) -> list:
    """
    Deep CEI analysis: for each external call, check if state changes
    happen AFTER the call (violation).
    """
    findings = []
    functions = _extract_functions(code)

    for func in functions:
        name = func["name"]
        body = func["body"]
        line = func["line"]

        # Find external calls in this function
        ext_calls = list(re.finditer(
            r'(\.call\{|\.transfer\(|\.send\(|\.delegatecall\{)',
            body
        ))

        for call in ext_calls:
            after_call = body[call.end():]
            call_line = body[:call.start()].count('\n') + line

            # Check for state changes AFTER this call
            state_changes = _find_state_changes(after_call)

            if state_changes:
                findings.append({
                    "type": "cei_violation",
                    "severity": "critical",
                    "function": name,
                    "line": call_line,
                    "call_type": call.group(1),
                    "state_changes_after": state_changes,
                    "detail": f"CEI violation in {name}(): state changes after external call"
                })

    return findings


def _extract_functions(code: str) -> list:
    """Extract functions with line numbers and bodies"""
    funcs = []
    pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{'
    for m in re.finditer(pattern, code):
        name = m.group(1)
        start = m.end()
        line = code[:m.start()].count('\n') + 1
        # Find matching closing brace
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == '{': depth += 1
            elif code[i] == '}': depth -= 1
            i += 1
        body = code[start:i-1]
        funcs.append({"name": name, "body": body, "line": line, "start": start, "end": i})
    return funcs


def _find_state_changes(code: str) -> list:
    """Find state variable assignments in code block"""
    patterns = [
        r'(\w+)\s*=\s*[^=]',           # Variable = value
        r'(\w+)\s*\+=\s*',             # Variable +=
        r'(\w+)\s*-=\s*',              # Variable -=
        r'\.push\(',                    # Array push
        r'mapping\([^)]*\)[^=]*=',     # Mapping assignment
        r'\.pop\(',                     # Array pop
    ]
    changes = []
    for pat in patterns:
        for m in re.finditer(pat, code):
            changes.append(m.group(0)[:40])
    return changes[:5]  # Limit output


# ═══════════════════════════════════════════
#  Vulnerability Signature Database
# ═══════════════════════════════════════════

SIGNATURES = [
    # === Reentrancy patterns ===
    {
        "id": "SIG-001",
        "name": "Reentrancy: CEI violation in transfer",
        "severity": "critical",
        "pattern": r'\.transfer\(.*\);\s*\n\s*\w+\s*=',
        "description": "State variable written AFTER transfer()",
        "real_exploit": "DAO hack (2016), Cream Finance (2021)",
    },
    {
        "id": "SIG-002",
        "name": "Reentrancy: Unchecked send",
        "severity": "high",
        "pattern": r'\.send\([^)]*\)(?!.*require)',
        "description": ".send() return value not checked",
        "real_exploit": "King of the Ether (2016)",
    },
    {
        "id": "SIG-003",
        "name": "Reentrancy: Cross-function",
        "severity": "critical",
        "pattern": r'(sharePrice|totalSupply|balance).*\.call\{',
        "description": "Price/supply dependent on external call result",
        "real_exploit": "Cream Finance (2021)",
    },

    # === Access control ===
    {
        "id": "SIG-004",
        "name": "Access: Unprotected initialize",
        "severity": "critical",
        "pattern": r'function\s+initialize\s*\([^)]*\)[^{]*\{(?!.*initializer)(?!.*onlyOwner)(?!.*require\(.*==.*owner)',
        "description": "initialize() callable by anyone",
        "real_exploit": "Parity Wallet (2017), Wormhole (skipped)",
    },
    {
        "id": "SIG-005",
        "name": "Access: tx.origin auth",
        "severity": "high",
        "pattern": r'require\s*\(\s*tx\.origin\s*==',
        "description": "tx.origin used for authorization",
        "real_exploit": "Numerous phishing attacks",
    },

    # === Oracle manipulation ===
    {
        "id": "SIG-006",
        "name": "Oracle: Spot price from AMM",
        "severity": "critical",
        "pattern": r'getReserves\(\)|\.balanceOf\(.*\).*price|getAmounts?Out\(',
        "description": "Using AMM spot price as oracle",
        "real_exploit": "Cream Finance (2021), Harvest Finance (2020)",
    },
    {
        "id": "SIG-007",
        "name": "Oracle: No staleness check",
        "severity": "high",
        "pattern": r'latestRoundData\(\)(?!.*updatedAt)(?!.*stale)',
        "description": "Chainlink price used without staleness check",
        "real_exploit": "Venus Protocol (2021)",
    },
    {
        "id": "SIG-008",
        "name": "Oracle: TWAP bypass",
        "severity": "high",
        "pattern": r'(?!.*cumulative)(?!.*twap)(swap|exchange).*price',
        "description": "Using instantaneous price instead of TWAP",
        "real_exploit": "Warp Finance (2020)",
    },

    # === Arithmetic ===
    {
        "id": "SIG-009",
        "name": "Arithmetic: Division before multiplication",
        "severity": "medium",
        "pattern": r'\/\s*\w+\s*\*',
        "description": "Precision loss from division before multiplication",
        "real_exploit": "Numerous DeFi precision losses",
    },
    {
        "id": "SIG-010",
        "name": "Arithmetic: Unsafe downcasting",
        "severity": "high",
        "pattern": r'uint(?!256)\d+\s*\(\s*\w+\s*\)',
        "description": "Downcasting can overflow silently",
        "real_exploit": "Multiple DeFi overflow bugs",
    },

    # === Flash loan ===
    {
        "id": "SIG-011",
        "name": "Flash loan: Uncollateralized borrow + swap",
        "severity": "critical",
        "pattern": r'(?:flashLoan|flashloan).*swap',
        "description": "Flash loan followed by swap in same tx",
        "real_exploit": "PancakeBunny (2021), Belt Finance (2021)",
    },
    {
        "id": "SIG-012",
        "name": "Flash loan: Price impact not checked",
        "severity": "high",
        "pattern": r'(?:swap|exchange)(?!.*minReturn)(?!.*amountOutMin)',
        "description": "Swap without minimum return check",
        "real_exploit": "bZx (2020), numerous MEV exploits",
    },

    # === Governance ===
    {
        "id": "SIG-013",
        "name": "Governance: No timelock",
        "severity": "critical",
        "pattern": r'function\s+execute\s*\([^)]*\)[^{]*\{(?!.*timelock)(?!.*delay)',
        "description": "Governance execution without timelock",
        "real_exploit": "Compound governance concerns",
    },
    {
        "id": "SIG-014",
        "name": "Governance: Flash loan voting",
        "severity": "high",
        "pattern": r'(getVotes|getPastVotes)(?!.*snapshot)',
        "description": "Voting power queryable without snapshot",
        "real_exploit": "Beanstalk (2022) — though different mechanism",
    },

    # === ERC-20 specific ===
    {
        "id": "SIG-015",
        "name": "ERC20: approve race condition",
        "severity": "high",
        "pattern": r'approve\s*\([^,]+,\s*[^)]+\)(?!.*increaseAllowance)(?!.*decreaseAllowance)(?!.*safeApprove)',
        "description": "Standard approve() vulnerable to race condition",
        "real_exploit": "Known ERC-20 frontrunning",
    },
    {
        "id": "SIG-016",
        "name": "ERC20: Fee-on-transfer not handled",
        "severity": "high",
        "pattern": r'transferFrom\([^)]+\)\s*\{[^}]*\}[^}]*mint',
        "description": "Possible fee-on-transfer token incompatibility",
        "real_exploit": "Multiple DeFi integrations",
    },

    # === Upgrade ===
    {
        "id": "SIG-017",
        "name": "Upgrade: No storage gap",
        "severity": "critical",
        "pattern": r'(UUPS|Transparent|Beacon).*?(?!__gap)(?!storageGap)',
        "description": "Upgradeable contract without storage gap",
        "real_exploit": "Multiple proxy storage collisions",
    },
    {
        "id": "SIG-018",
        "name": "Upgrade: Selfdestruct in implementation",
        "severity": "critical",
        "pattern": r'UUPSUpgradeable.*selfdestruct|selfdestruct.*implementation',
        "description": "Upgradeable contract with selfdestruct",
        "real_exploit": "Parity multisig (2017)",
    },

    # === MEV ===
    {
        "id": "SIG-019",
        "name": "MEV: Sandwichable swap",
        "severity": "high",
        "pattern": r'(?:swap|exchange)\s*\([^)]*\)(?!.*deadline)(?!.*sqrtPriceLimit)',
        "description": "Swap without deadline or price limit",
        "real_exploit": "Millions lost to sandwich attacks daily",
    },
    {
        "id": "SIG-020",
        "name": "MEV: Frontrunnable init",
        "severity": "high",
        "pattern": r'(?:initialize|init)\s*\([^)]*\)[^{]*\{(?!.*onlyOwner)(?!.*initializer)',
        "description": "Initialization can be frontrun",
        "real_exploit": "Parity Wallet, numerous DeFi",
    },

    # === Cross-chain ===
    {
        "id": "SIG-021",
        "name": "Bridge: Missing chainId",
        "severity": "critical",
        "pattern": r'(?:sendMessage|relayMessage|lzReceive)(?!.*chainId)(?!.*block\.chainid)',
        "description": "Cross-chain message without chainId binding",
        "real_exploit": "Nomad Bridge (2022) — different but related",
    },
    {
        "id": "SIG-022",
        "name": "Bridge: Unbounded mint",
        "severity": "critical",
        "pattern": r'function\s+mint\s*\(.*bridge.*\)(?!.*cap)(?!.*limit)',
        "description": "Bridge mint without supply cap",
        "real_exploit": "Wormhole (2022), Poly Network (2021)",
    },

    # === Staking ===
    {
        "id": "SIG-023",
        "name": "Staking: Flash stake attack",
        "severity": "high",
        "pattern": r'(?:stake|deposit).*getReward(?!.*lock)(?!.*vesting)',
        "description": "Rewards claimable immediately after stake",
        "real_exploit": "Multiple DeFi yield exploits",
    },
    {
        "id": "SIG-024",
        "name": "Staking: Inflation without cap",
        "severity": "medium",
        "pattern": r'mintReward\s*\([^)]*\)(?!.*maxSupply)(?!.*cap)',
        "description": "Reward minting without global cap",
        "real_exploit": "Multiple token inflation bugs",
    },

    # === Vault ===
    {
        "id": "SIG-025",
        "name": "Vault: ERC4626 inflation attack",
        "severity": "critical",
        "pattern": r'ERC4626.*deposit(?!.*deadShares)(?!.*MINIMUM_SHARES)(?!.*decimalsOffset)',
        "description": "ERC4626 vault vulnerable to first-depositor inflation",
        "real_exploit": "Multiple ERC4626 vault exploits",
    },

    # ═══════════════════════════════════════════
    #  26-35: Advanced Reentrancy + Call Patterns
    # ═══════════════════════════════════════════
    {
        "id": "SIG-026", "name": "Reentrancy: Read-only reentrancy",
        "severity": "critical",
        "pattern": r'view\s+function.*\.call\{',
        "description": "View function used during reentrancy — read-only attack",
        "real_exploit": "Curve/Vyper reentrancy (2023)",
    },
    {
        "id": "SIG-027", "name": "Reentrancy: Token callback",
        "severity": "high",
        "pattern": r'safeTransfer.*\(.*\).*\{[^}]*mint',
        "description": "ERC777/ERC721 callback reentrancy via safeTransfer",
        "real_exploit": "Uniswap V1 + ERC777 (2019)",
    },
    {
        "id": "SIG-028", "name": "Low-level call to arbitrary address",
        "severity": "high",
        "pattern": r'\.call\{value:.*\}\(.*msg\.sender',
        "description": ".call to user-controlled address — reentrancy or selfdestruct risk",
        "real_exploit": "Multiple DeFi exploits",
    },
    {
        "id": "SIG-029", "name": "Delegatecall to user input",
        "severity": "critical",
        "pattern": r'\.delegatecall\(.*calldata',
        "description": "delegatecall with user-supplied calldata — code execution",
        "real_exploit": "Parity multisig (2017)",
    },
    {
        "id": "SIG-030", "name": "Unchecked external call in loop",
        "severity": "high",
        "pattern": r'for\s*\([^)]*\)[^{]*\{[^}]*\.call\{',
        "description": "External call inside loop — gas bomb + one failure blocks all",
        "real_exploit": "Multiple DoS attacks",
    },

    # ═══════════════════════════════════════════
    #  31-40: Oracle + Price Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-031", "name": "Oracle: Single source no fallback",
        "severity": "high",
        "pattern": r'(?:onlyOracle|single.*oracle|one.*price).*getPrice',
        "description": "Single oracle source with no fallback — single point of failure",
        "real_exploit": "Venus Protocol (2021)",
    },
    {
        "id": "SIG-032", "name": "Oracle: Decimals mismatch",
        "severity": "high",
        "pattern": r'price.*\*\s*1e18.*\/\s*1e(?:6|8)',
        "description": "Oracle decimal conversion risks precision loss",
        "real_exploit": "Multiple oracle integration bugs",
    },
    {
        "id": "SIG-033", "name": "Oracle: No sequencer uptime check on L2",
        "severity": "high",
        "pattern": r'(?:Arbitrum|Optimism|Base).*Chainlink(?!.*sequencer)',
        "description": "L2 Chainlink oracle missing sequencer uptime check",
        "real_exploit": "L2 oracle stale during sequencer downtime",
    },
    {
        "id": "SIG-034", "name": "Oracle: Circular dependency",
        "severity": "critical",
        "pattern": r'price.*from.*same.*pool|pool.*price.*own.*token',
        "description": "Oracle pricing own token via own pool — infinite loop risk",
        "real_exploit": "Multiple DeFi oracle loops",
    },
    {
        "id": "SIG-035", "name": "Oracle: Unchecked return for zero price",
        "severity": "critical",
        "pattern": r'(?:getPrice|latestAnswer)\s*\(\s*\)(?!.*require.*>.*0)',
        "description": "Oracle price not validated for zero — division by zero or zero-price exploit",
        "real_exploit": "Multiple zero-price exploits",
    },

    # ═══════════════════════════════════════════
    #  36-45: Access Control Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-036", "name": "Access: Role grant without timelock",
        "severity": "critical",
        "pattern": r'grantRole\s*\(.*(?:DEFAULT_ADMIN|MINTER|UPGRADER)(?!.*timelock)',
        "description": "Critical role granted without timelock — instant privilege escalation",
        "real_exploit": "Multiple governance attacks",
    },
    {
        "id": "SIG-037", "name": "Access: Missing two-step ownership transfer",
        "severity": "high",
        "pattern": r'function\s+transferOwnership\s*\([^)]*\)[^{]*\{[^}]*owner\s*=\s*\w+\s*;(?!.*pending)',
        "description": "Single-step ownership transfer — can be bricked by wrong address",
        "real_exploit": "Multiple accidental ownership losses",
    },
    {
        "id": "SIG-038", "name": "Access: Public burn without auth",
        "severity": "high",
        "pattern": r'function\s+burn\s*\([^)]*\)[^{]*\{(?!.*onlyOwner)(?!.*require\(msg\.sender)',
        "description": "Token burn callable by anyone — supply manipulation",
        "real_exploit": "Multiple token exploits",
    },
    {
        "id": "SIG-039", "name": "Access: renounceOwnership available",
        "severity": "medium",
        "pattern": r'renounceOwnership\s*\(\s*\)',
        "description": "renounceOwnership() not overridden — permanent loss of admin",
        "real_exploit": "Multiple DeFi admin losses",
    },
    {
        "id": "SIG-040", "name": "Access: Delegatecall to self via fallback",
        "severity": "critical",
        "pattern": r'fallback\s*\(\s*\)[^{]*\{[^}]*delegatecall',
        "description": "Fallback function delegates to arbitrary code — proxy pattern risk",
        "real_exploit": "Parity wallet (2017)",
    },

    # ═══════════════════════════════════════════
    #  41-50: Flash Loan + MEV Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-041", "name": "MEV: Block.coinbase dependency",
        "severity": "medium",
        "pattern": r'block\.coinbase',
        "description": "block.coinbase used — miner can manipulate",
        "real_exploit": "Miner-extractable patterns",
    },
    {
        "id": "SIG-042", "name": "MEV: gasprice oracle",
        "severity": "low",
        "pattern": r'tx\.gasprice',
        "description": "tx.gasprice used as oracle — miner can manipulate",
        "real_exploit": "Gas price oracle manipulation",
    },
    {
        "id": "SIG-043", "name": "Flash loan: No fee check",
        "severity": "high",
        "pattern": r'(?:flashLoan|flashloan).*\(.*\)(?!.*fee)',
        "description": "Flash loan callback doesn't verify fee — attacker can drain",
        "real_exploit": "Multiple flash loan exploits",
    },
    {
        "id": "SIG-044", "name": "Flash loan: Reentrancy in callback",
        "severity": "critical",
        "pattern": r'onFlashLoan.*\{[^}]*swap',
        "description": "Flash loan callback with swap — reentrancy via price impact",
        "real_exploit": "Cream Finance (2021)",
    },
    {
        "id": "SIG-045", "name": "MEV: Unprotected mempool view",
        "severity": "high",
        "pattern": r'mempool|pending.*transaction',
        "description": "Code references mempool — MEV bot detection, not exploitable but design smell",
        "real_exploit": "MEV searcher patterns",
    },

    # ═══════════════════════════════════════════
    #  46-55: Upgrade + Proxy Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-046", "name": "Proxy: Implementation not initialized",
        "severity": "critical",
        "pattern": r'UUPS.*deploy(?!.*initialize\()',
        "description": "UUPS implementation deployed without initialization — takeover risk",
        "real_exploit": "Multiple UUPS takeovers",
    },
    {
        "id": "SIG-047", "name": "Proxy: Beacon not validated",
        "severity": "high",
        "pattern": r'BeaconProxy(?!.*beacon.*!=.*address\(0\))',
        "description": "BeaconProxy without beacon address validation",
        "real_exploit": "Multiple beacon exploits",
    },
    {
        "id": "SIG-048", "name": "Proxy: Transparent proxy selector clash",
        "severity": "medium",
        "pattern": r'TransparentUpgradeableProxy',
        "description": "Transparent proxy may have selector clashes with implementation",
        "real_exploit": "Known proxy selector issues",
    },
    {
        "id": "SIG-049", "name": "Upgrade: No upgrade delay",
        "severity": "high",
        "pattern": r'upgradeTo\s*\([^)]*\)(?!.*timelock)(?!.*delay)',
        "description": "Instant upgrade without timelock — rug pull risk",
        "real_exploit": "Multiple DeFi rug pulls",
    },
    {
        "id": "SIG-050", "name": "Proxy: Implementation can selfdestruct",
        "severity": "critical",
        "pattern": r'(?:UUPS|proxy).*selfdestruct',
        "description": "Proxy implementation can selfdestruct — bricks all proxies",
        "real_exploit": "Parity multisig (2017) — $280M frozen",
    },

    # ═══════════════════════════════════════════
    #  51-60: Token + ERC Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-051", "name": "Token: No return value check on transfer",
        "severity": "high",
        "pattern": r'IERC20\([^)]+\)\.transfer\([^)]+\)(?!.*require)',
        "description": "ERC20 transfer result not checked — USDT non-standard return",
        "real_exploit": "Multiple DeFi token incompatibility",
    },
    {
        "id": "SIG-052", "name": "Token: Infinite approval",
        "severity": "medium",
        "pattern": r'approve\s*\([^,]+,\s*(?:type\(uint256\)\.max|2\*\*256\s*-\s*1)',
        "description": "Infinite token approval — all funds at risk if contract exploited",
        "real_exploit": "Standard practice but high risk",
    },
    {
        "id": "SIG-053", "name": "Token: Missing permit deadline validation",
        "severity": "high",
        "pattern": r'permit\s*\([^)]*deadline[^)]*\)[^{]*\{[^}]*(?!.*require\(deadline)',
        "description": "Permit deadline stored but not validated — expired permits accepted",
        "real_exploit": "Multiple permit exploits",
    },
    {
        "id": "SIG-054", "name": "ERC721: No receiver check on mint",
        "severity": "medium",
        "pattern": r'_mint\s*\([^)]*\)(?!.*_checkOnERC721Received)',
        "description": "ERC721 mint without receiver check — tokens to contract addresses",
        "real_exploit": "Numerous stuck NFT issues",
    },
    {
        "id": "SIG-055", "name": "Token: Fee-on-transfer not handled in swap",
        "severity": "high",
        "pattern": r'(?:swap|exchange).*transferFrom(?!.*balanceBefore)(?!.*balanceAfter)',
        "description": "Swap without balance-diff check — fee-on-transfer tokens steal value",
        "real_exploit": "Multiple DeFi fee-on-transfer exploits",
    },

    # ═══════════════════════════════════════════
    #  56-65: Lending + Vault Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-056", "name": "Lending: Interest rate manipulation",
        "severity": "high",
        "pattern": r'utilization.*rate.*borrow|borrow.*rate.*util',
        "description": "Interest rate based on manipulable utilization",
        "real_exploit": "Multiple lending protocol exploits",
    },
    {
        "id": "SIG-057", "name": "Lending: Share price rounding attack",
        "severity": "critical",
        "pattern": r'convertToShares|convertToAssets.*\/(?!.*\+\s*1)',
        "description": "Share conversion without rounding protection — vault inflation",
        "real_exploit": "Multiple vault exploits (2023)",
    },
    {
        "id": "SIG-058", "name": "Vault: totalAssets includes donations",
        "severity": "critical",
        "pattern": r'totalAssets.*balanceOf\(address\(this\)\)',
        "description": "totalAssets uses raw balance — donation attack inflates share price",
        "real_exploit": "Multiple ERC4626 donation attacks",
    },
    {
        "id": "SIG-059", "name": "Lending: No bad debt handling",
        "severity": "high",
        "pattern": r'(?:borrow|lend).*\([^)]*\)(?!.*badDebt)(?!.*insolvent)',
        "description": "Lending protocol without bad debt mechanism — insolvency risk",
        "real_exploit": "Multiple lending protocol failures",
    },
    {
        "id": "SIG-060", "name": "Lending: Liquidation without incentive",
        "severity": "high",
        "pattern": r'function\s+liquidate\s*\([^)]*\)[^{]*\{(?!.*(?:bonus|discount|incentive))',
        "description": "Liquidation without keeper incentive — bad debt accumulates",
        "real_exploit": "Multiple DeFi bad debt crises",
    },

    # ═══════════════════════════════════════════
    #  66-75: AMM + Swap Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-061", "name": "AMM: No deadline on swap",
        "severity": "high",
        "pattern": r'(?:swap|exchange)\s*\([^)]*\)(?!.*deadline)',
        "description": "Swap without deadline — stale transaction MEV risk",
        "real_exploit": "Daily MEV exploits",
    },
    {
        "id": "SIG-062", "name": "AMM: Impermanent loss ignored",
        "severity": "medium",
        "pattern": r'(?:addLiquidity|deposit).*\([^)]*\)(?!.*slippage)(?!.*min)',
        "description": "Liquidity provision without min shares — sandwich attack on LPs",
        "real_exploit": "Multiple LP sandwich attacks",
    },
    {
        "id": "SIG-063", "name": "AMM: Fee switch not implemented",
        "severity": "low",
        "pattern": r'(?:swap|exchange)\s*\([^)]*\)(?!.*fee)',
        "description": "Swap function without protocol fee — revenue leakage",
        "real_exploit": "Uniswap V2 fee switch debate",
    },
    {
        "id": "SIG-064", "name": "AMM: sqrtPriceLimitX96 not used",
        "severity": "high",
        "pattern": r'Uniswap.*swap(?!.*sqrtPriceLimitX96)',
        "description": "Uniswap V3 swap without price limit — unlimited slippage",
        "real_exploit": "Multiple Uniswap V3 MEV exploits",
    },
    {
        "id": "SIG-065", "name": "AMM: Pool creation without checks",
        "severity": "medium",
        "pattern": r'createPool\s*\([^)]*\)(?!.*require)',
        "description": "Pool creation without validation — fake pool attack",
        "real_exploit": "Multiple DeFi pool scams",
    },

    # ═══════════════════════════════════════════
    #  76-85: Bridge + Cross-chain Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-066", "name": "Bridge: No message ordering guarantee",
        "severity": "high",
        "pattern": r'(?:sendMessage|lzSend).*(?!.*nonce)(?!.*sequence)',
        "description": "Cross-chain message without sequence number — order manipulation",
        "real_exploit": "Multiple bridge exploits",
    },
    {
        "id": "SIG-067", "name": "Bridge: No relayer validation",
        "severity": "critical",
        "pattern": r'(?:relayer|messenger).*\([^)]*\)(?!.*trusted)(?!.*whitelist)',
        "description": "Cross-chain relayer without trusted list — anyone can relay messages",
        "real_exploit": "Nomad Bridge ($190M, 2022)",
    },
    {
        "id": "SIG-068", "name": "Bridge: No rate limit on mints",
        "severity": "critical",
        "pattern": r'function\s+mint\s*\(.*(?:bridge|cross).*\)(?!.*rateLimit)(?!.*daily)',
        "description": "Cross-chain mint without rate limit — unlimited exploit window",
        "real_exploit": "Wormhole ($326M, 2022)",
    },
    {
        "id": "SIG-069", "name": "Bridge: No emergency pause",
        "severity": "high",
        "pattern": r'(?:bridge|cross.chain).*(?!.*pause)(?!.*emergency)(?!.*circuit)',
        "description": "Bridge without emergency pause — no circuit breaker during exploit",
        "real_exploit": "Multiple bridge hacks without pause mechanism",
    },
    {
        "id": "SIG-070", "name": "Bridge: Multi-sig without threshold check",
        "severity": "high",
        "pattern": r'(?:guardian|validator|signer).*length(?!.*threshold)(?!.*required)',
        "description": "Guardian count without threshold validation — can be bypassed",
        "real_exploit": "Wormhole guardian bypass ($326M)",
    },

    # ═══════════════════════════════════════════
    #  86-95: Gas + DoS + Misc
    # ═══════════════════════════════════════════
    {
        "id": "SIG-071", "name": "DoS: Unbounded loop over user input",
        "severity": "high",
        "pattern": r'for\s*\([^;]*;\s*\w+\.length[^;]*;[^)]*\)[^{]*\{[^}]*\.transfer',
        "description": "Loop over user-supplied array with external calls — gas griefing",
        "real_exploit": "Multiple DoS attacks",
    },
    {
        "id": "SIG-072", "name": "DoS: Block gas limit dependency",
        "severity": "medium",
        "pattern": r'for\s*\([^;]*;\s*\w+\s*<\s*\d{3,}[^;]*;',
        "description": "Fixed high-count loop — may hit block gas limit",
        "real_exploit": "Multiple gas limit DoS",
    },
    {
        "id": "SIG-073", "name": "DoS: External call can revert",
        "severity": "medium",
        "pattern": r'\.call\{[^}]*\}\("".*\)(?!.*try)',
        "description": "Unprotected external call — one revert blocks all",
        "real_exploit": "Multiple DoS via revert",
    },
    {
        "id": "SIG-074", "name": "Gas: Storage write in loop",
        "severity": "low",
        "pattern": r'for\s*\([^)]*\)[^{]*\{[^}]*\w+\s*=\s*[^=]',
        "description": "Storage write inside loop — extreme gas cost",
        "real_exploit": "Common gas inefficiency",
    },
    {
        "id": "SIG-075", "name": "Gas: Redundant SSTORE",
        "severity": "low",
        "pattern": r'=\s*0;\s*$',
        "description": "Setting storage to zero — refunds gas but may indicate pattern",
        "real_exploit": "Gas golfing patterns",
    },

    # ═══════════════════════════════════════════
    #  76-100: Staking + Rewards + Governance Deep
    # ═══════════════════════════════════════════
    {
        "id": "SIG-076", "name": "Staking: Deposit without min shares",
        "severity": "high",
        "pattern": r'(?:stake|deposit)\s*\([^)]*\)(?!.*min)', 
        "description": "Staking without minimum shares check — inflation attack on first depositor",
        "real_exploit": "Multiple staking exploits",
    },
    {
        "id": "SIG-077", "name": "Rewards: No checkpoint before update",
        "severity": "high",
        "pattern": r'(?:rewardPerToken|rewardRate)\s*=\s*[^=].*\n(?!.*updateReward)',
        "description": "Reward rate changed without checkpointing — retroactive reward manipulation",
        "real_exploit": "Multiple reward manipulation exploits",
    },
    {
        "id": "SIG-078", "name": "Rewards: Fixed duration infinite mint",
        "severity": "critical",
        "pattern": r'(?:notifyReward|addReward)\s*\([^)]*\)(?!.*periodFinish)(?!.*cap)',
        "description": "Reward notification without period cap — infinite reward inflation",
        "real_exploit": "Multiple yield farming exploits",
    },
    {
        "id": "SIG-079", "name": "Governance: Proposal without quorum",
        "severity": "high",
        "pattern": r'(?:propose|createProposal)\s*\([^)]*\)(?!.*quorum)',
        "description": "Proposal creation without quorum requirement — spam or minority attack",
        "real_exploit": "Multiple governance attacks",
    },
    {
        "id": "SIG-080", "name": "Governance: Voting power delegation exploit",
        "severity": "high",
        "pattern": r'delegate\s*\([^)]*\)(?!.*lock)(?!.*vest)',
        "description": "Delegation without lock — flash-delegate attack",
        "real_exploit": "Multiple governance delegation exploits",
    },
    {
        "id": "SIG-081", "name": "Multicall: Unchecked delegatecall",
        "severity": "critical",
        "pattern": r'multicall.*delegatecall',
        "description": "Multicall with delegatecall to arbitrary target — selfdestruct risk",
        "real_exploit": "Multiple multicall exploits",
    },
    {
        "id": "SIG-082", "name": "ERC2771: Trusted forwarder spoofing",
        "severity": "critical",
        "pattern": r'(?:isTrustedForwarder|_msgSender).*\([^)]*\)(?!.*only)',
        "description": "ERC2771 trusted forwarder check without only modifier",
        "real_exploit": "Multiple meta-transaction exploits",
    },
    {
        "id": "SIG-083", "name": "UUPS: upgradeToAndCall data injection",
        "severity": "critical",
        "pattern": r'upgradeToAndCall\s*\([^,]+,\s*[^)]*data',
        "description": "UUPS upgrade with arbitrary data — can selfdestruct during upgrade",
        "real_exploit": "Multiple UUPS exploits",
    },
    {
        "id": "SIG-084", "name": "Create2: Predictable address collision",
        "severity": "high",
        "pattern": r'CREATE2|create2\s*\(.*salt',
        "description": "CREATE2 with predictable salt — address collision attack",
        "real_exploit": "Multiple CREATE2 exploits",
    },
    {
        "id": "SIG-085", "name": "Assembly: Unchecked return data",
        "severity": "high",
        "pattern": r'assembly\s*\{[^}]*delegatecall(?!.*returndatasize)',
        "description": "Assembly delegatecall without checking return data size",
        "real_exploit": "Multiple low-level call exploits",
    },

    # ═══════════════════════════════════════════
    #  86-100: More Real Exploit Patterns
    # ═══════════════════════════════════════════
    {
        "id": "SIG-086", "name": "Reentrancy: NFT onERC721Received callback",
        "severity": "high",
        "pattern": r'safeTransferFrom.*\{[^}]*withdraw',
        "description": "NFT safeTransfer with withdrawal — callback reentrancy",
        "real_exploit": "Multiple NFT marketplace exploits",
    },
    {
        "id": "SIG-087", "name": "Withdraw: No balance-after check",
        "severity": "high",
        "pattern": r'withdraw\s*\([^)]*\)[^{]*\{[^}]*(?:\.transfer|\.call\{)(?!.*balanceBefore|balanceAfter)',
        "description": "Withdraw without pre/post balance check — fee-on-transfer risk",
        "real_exploit": "Multiple withdrawal exploits",
    },
    {
        "id": "SIG-088", "name": "Swap: Path manipulation via user input",
        "severity": "high",
        "pattern": r'(?:path|route)\s*\[\s*\].*msg\.sender|msg\.sender.*(?:path|route)',
        "description": "Swap path from user input — attacker controls which pools are used",
        "real_exploit": "Multiple DEX router exploits",
    },
    {
        "id": "SIG-089", "name": "Oracle: TWAP window too short",
        "severity": "high",
        "pattern": r'(?:TWAP|twap).*(?:1\s*minute|5\s*minute|60\s*second)',
        "description": "TWAP with very short window — manipulable via flash loan",
        "real_exploit": "Multiple TWAP manipulation exploits",
    },
    {
        "id": "SIG-090", "name": "Proxy: initialize function without modifier",
        "severity": "critical",
        "pattern": r'function\s+initialize\s*\([^)]*\)\s*(?:public|external)\s*\{',
        "description": "Public initialize without initializer modifier — can be called repeatedly",
        "real_exploit": "Multiple UUPS initialization exploits",
    },
    {
        "id": "SIG-091", "name": "Access: Ownable without renounce override",
        "severity": "medium",
        "pattern": r'import.*Ownable(?!.*renounceOwnership.*override)',
        "description": "Ownable imported without overriding renounceOwnership",
        "real_exploit": "Multiple accidental ownership losses",
    },
    {
        "id": "SIG-092", "name": "Lending: Collateral ratio < 100%",
        "severity": "high",
        "pattern": r'(?:collateralRatio|LTV|collateral_factor)\s*[><=]\s*(?:0?\.[89]|1\.?[0-9])',
        "description": "Collateral ratio too high — underwater positions during volatility",
        "real_exploit": "Multiple lending market crashes",
    },
    {
        "id": "SIG-093", "name": "Token: Mint without supply cap",
        "severity": "critical",
        "pattern": r'function\s+mint\s*\([^)]*\)[^{]*\{(?!.*maxSupply)(?!.*cap)(?!.*limit)',
        "description": "Mint function without supply cap — infinite inflation possible",
        "real_exploit": "Multiple token supply exploits",
    },
    {
        "id": "SIG-094", "name": "Reentrancy: via receive/fallback",
        "severity": "critical",
        "pattern": r'receive\s*\(\s*\)\s*external\s*payable\s*\{[^}]*\.call',
        "description": "receive() function makes external calls — self-reentrancy possible",
        "real_exploit": "Multiple receive() reentrancy exploits",
    },
    {
        "id": "SIG-095", "name": "Storage: Uninitialized implementation",
        "severity": "critical",
        "pattern": r'(?:UUPS|proxy).*deploy(?!.*_disableInitializers)',
        "description": "UUPS implementation deployed without disabling initializers",
        "real_exploit": "Multiple UUPS takeovers via uninitialized implementation",
    },
    {
        "id": "SIG-096", "name": "Signature: Missing typehash",
        "severity": "high",
        "pattern": r'(?:keccak256|abi\.encode).*sign(?!.*_TYPEHASH)(?!.*typeHash)',
        "description": "Signature without EIP-712 typehash — cross-contract replay risk",
        "real_exploit": "Multiple signature replay exploits",
    },
    {
        "id": "SIG-097", "name": "Oracle: Price staleness during volatility",
        "severity": "high",
        "pattern": r'(?:heartbeat|staleness).*(?:24\s*hour|86400)',
        "description": "24h staleness threshold — price can be stale during crash",
        "real_exploit": "Venus Protocol ($200M, 2021)",
    },
    {
        "id": "SIG-098", "name": "Lending: Oracle price used directly",
        "severity": "high",
        "pattern": r'price\s*=\s*\w+\.(?:latestAnswer|getPrice)\s*\([^)]*\)\s*;(?!.*\*)',
        "description": "Raw oracle price used directly without safety margin",
        "real_exploit": "Multiple oracle-based liquidations",
    },
    {
        "id": "SIG-099", "name": "Gas: Dynamic array in storage",
        "severity": "low",
        "pattern": r'(?:address|uint256|bytes32)\[\]\s+(?:public|private|internal)\s+\w+\s*;',
        "description": "Unbounded dynamic array in storage — gas grows unboundedly",
        "real_exploit": "Common gas anti-pattern",
    },
    {
        "id": "SIG-100", "name": "Time: block.timestamp precision",
        "severity": "low",
        "pattern": r'block\.timestamp\s*[%\/]',
        "description": "block.timestamp used in modulo/division — miner can bias by ±15s",
        "real_exploit": "Multiple timestamp manipulation exploits",
    },
]


def run_signature_scan(code: str) -> list:
    """Scan code against known vulnerability signatures"""
    findings = []
    for sig in SIGNATURES:
        try:
            if re.search(sig["pattern"], code, re.DOTALL | re.IGNORECASE):
                findings.append({
                    "type": "signature_match",
                    "sig_id": sig["id"],
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "real_exploit": sig["real_exploit"],
                })
        except re.error:
            continue
    return findings


def deep_audit(code: str) -> dict:
    """Full deep audit: CEI + Signature DB"""
    cei_findings = check_cei_pattern(code)
    sig_findings = run_signature_scan(code)

    all_findings = cei_findings + sig_findings
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_findings": len(all_findings),
        "cei_findings": len(cei_findings),
        "signature_findings": len(sig_findings),
        "severity_counts": severity_counts,
        "findings": all_findings,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python deep_audit.py <file.sol>")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        code = f.read()

    result = deep_audit(code)
    print(json.dumps(result, ensure_ascii=False, indent=2))
