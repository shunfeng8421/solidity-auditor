#!/usr/bin/env python3
"""
Pre-Audit Threat Modeler — 对标 Codex security-threat-model skill
审计前自动识别: 攻击面、信任边界、资产分类、角色风险
"""
import re
import json

def build_threat_model(code: str, filename: str) -> dict:
    """Build a threat model from Solidity source code"""

    # 1. Asset identification
    assets = _identify_assets(code)

    # 2. Attack surface mapping
    attack_surface = _map_attack_surface(code)

    # 3. Trust boundaries
    trust_boundaries = _identify_trust_boundaries(code)

    # 4. Role risk assessment
    roles = _assess_roles(code)

    # 5. External integrations
    externals = _identify_externals(code)

    return {
        "file": filename,
        "assets": assets,
        "attack_surface": attack_surface,
        "trust_boundaries": trust_boundaries,
        "roles": roles,
        "externals": externals,
        "risk_level": _calculate_risk(attack_surface, trust_boundaries, roles),
    }


def _identify_assets(code: str) -> list:
    """Identify valuable assets in the contract"""
    assets = []

    # ERC20 tokens
    if re.search(r'(?:ERC20|IERC20|transfer|balanceOf)', code):
        assets.append({"type": "token", "name": "ERC20 Token", "risk": "high"})

    # Native ETH
    if re.search(r'(?:msg\.value|payable|address\(this\)\.balance)', code):
        assets.append({"type": "native", "name": "ETH/Matic", "risk": "high"})

    # Vault / pooled funds
    if re.search(r'(?:vault|pool|totalValueLocked|TVL|totalAssets)', code, re.IGNORECASE):
        assets.append({"type": "pool", "name": "Pooled Funds", "risk": "critical"})

    # NFTs
    if re.search(r'(?:ERC721|mint|tokenURI)', code):
        assets.append({"type": "nft", "name": "NFT", "risk": "medium"})

    # Governance power
    if re.search(r'(?:vote|governor|propose|delegate)', code, re.IGNORECASE):
        assets.append({"type": "governance", "name": "Voting Power", "risk": "high"})

    # Oracle price data
    if re.search(r'(?:oracle|priceFeed|latestRoundData|getPrice)', code):
        assets.append({"type": "oracle", "name": "Price Feed", "risk": "critical"})

    # Signatures / auth
    if re.search(r'(?:ecrecover|permit|ECDSA|signature)', code):
        assets.append({"type": "auth", "name": "Signature Auth", "risk": "high"})

    if not assets:
        assets.append({"type": "unknown", "name": "Unidentified", "risk": "medium"})

    return assets


def _map_attack_surface(code: str) -> list:
    """Map all externally accessible functions"""
    surface = []
    funcs = re.findall(r'function\s+(\w+)\s*\(([^)]*)\)\s*(external|public)', code)

    for name, params, vis in funcs:
        risk = "low"
        if any(kw in name.lower() for kw in ['withdraw','mint','burn','transfer','swap']):
            risk = "critical"
        elif any(kw in name.lower() for kw in ['deposit','stake','lend','borrow','liquidate']):
            risk = "high"
        elif any(kw in name.lower() for kw in ['set','update','pause','unpause','upgrade']):
            risk = "high"
        elif any(kw in name.lower() for kw in ['claim','redeem','execute','fill']):
            risk = "medium"

        surface.append({
            "function": name,
            "visibility": vis,
            "params": params[:80],
            "risk": risk,
        })

    if not surface:
        surface.append({"function": "N/A", "risk": "low"})

    return surface


def _identify_trust_boundaries(code: str) -> list:
    """Identify trust boundaries and privileged roles"""
    boundaries = []

    # Ownable / AccessControl
    if 'onlyOwner' in code:
        boundaries.append({"type": "owner", "trust": "full", "risk": "single point of failure"})
    if 'AccessControl' in code or 'DEFAULT_ADMIN_ROLE' in code:
        boundaries.append({"type": "rbac", "trust": "role-based", "risk": "role escalation"})

    # Upgradeable
    if re.search(r'(?:UUPS|Transparent|upgradeable|upgradeTo)', code):
        boundaries.append({"type": "proxy", "trust": "upgrader", "risk": "storage collision + rug"})

    # Timelock
    if 'timelock' in code.lower() or 'TimelockController' in code:
        boundaries.append({"type": "timelock", "trust": "delayed", "risk": "governance delay bypass"})

    # Multisig
    if 'multisig' in code.lower() or 'MultiSig' in code:
        boundaries.append({"type": "multisig", "trust": "n-of-m", "risk": "signer collusion"})

    # Pausable
    if 'Pausable' in code or 'whenNotPaused' in code:
        boundaries.append({"type": "pausable", "trust": "pauser", "risk": "DoS by pauser"})

    if not boundaries:
        boundaries.append({"type": "none", "trust": "unknown"})

    return boundaries


def _assess_roles(code: str) -> list:
    """Assess role-based access control risks"""
    roles = []

    role_pattern = r'(?:bytes32\s+(?:public|private|internal)?\s*(\w+_ROLE)|keccak256\("(\w+)"\))'
    for m in re.finditer(role_pattern, code):
        role_name = m.group(1) or m.group(2) or "UNKNOWN"
        risk = "medium"
        if any(kw in role_name.upper() for kw in ['ADMIN','OWNER','UPGRADER','GOVERNOR']):
            risk = "critical"
        elif any(kw in role_name.upper() for kw in ['PAUSER','GUARDIAN','MINTER','BURNER']):
            risk = "high"
        roles.append({"role": role_name, "risk": risk})

    # Count onlyOwner usage as a role
    if 'onlyOwner' in code and not roles:
        roles.append({"role": "OWNER (onlyOwner)", "risk": "critical"})

    if not roles:
        roles.append({"role": "N/A", "risk": "unknown"})

    return roles[:10]


def _identify_externals(code: str) -> list:
    """Identify external protocol integrations"""
    externals = []

    if 'Chainlink' in code or 'AggregatorV3' in code:
        externals.append({"protocol": "Chainlink", "type": "oracle", "risk": "data manipulation"})
    if 'Uniswap' in code or 'IUniswap' in code:
        externals.append({"protocol": "Uniswap", "type": "DEX", "risk": "price manipulation"})
    if 'Aave' in code or 'IAave' in code:
        externals.append({"protocol": "Aave", "type": "lending", "risk": "pool insolvency"})
    if re.search(r'(?:LayerZero|lzSend|OFT)', code):
        externals.append({"protocol": "LayerZero", "type": "bridge", "risk": "message forgery"})
    if 'OpenZeppelin' in code or '@openzeppelin' in code:
        externals.append({"protocol": "OpenZeppelin", "type": "library", "risk": "supply chain"})

    if not externals:
        externals.append({"protocol": "N/A", "risk": "none"})

    return externals


def _calculate_risk(surface, boundaries, roles) -> str:
    """Calculate overall risk level"""
    score = 0
    crit_funcs = sum(1 for f in surface if f.get("risk") == "critical")
    high_funcs = sum(1 for f in surface if f.get("risk") == "high")
    crit_roles = sum(1 for r in roles if r.get("risk") == "critical")

    score += crit_funcs * 10 + high_funcs * 5 + crit_roles * 8

    if score >= 30: return "CRITICAL"
    if score >= 15: return "HIGH"
    if score >= 5: return "MEDIUM"
    return "LOW"
