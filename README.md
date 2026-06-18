# Solidity Auditor ⛓️🔍

**75+ automated security checks for Solidity smart contracts**
Reentrancy, access control, DeFi exploits, CEI violations, threat modeling.

## Quick Start
```bash
python auditor_v3.py --path contract.sol
python auditor_v3.py --dir contracts/
python auditor.py --dir contracts/   # baseline (25 rules)
```

## 3-Layer Detection
| Layer | Checks | Coverage |
|-------|--------|----------|
| Layer 1 — Rules | 50 regex | Reentrancy, access control, arithmetic |
| Layer 2 — DeFi | 25 checks | Flash loan, MEV, governance, oracle |
| Layer 3 — Deep | 25+ sigs | CEI pattern, threat model, cross-contract |

## Modules
`cross_contract.py` `threat_model.py` `slither_wrapper.py` `foundry_adapter.py` `ownership.py` `watchdog.py`

## Scoring
100-point scale: A(80+) B(60-79) C(40-59) D(0-39)

## Validation
Tested against Ethernaut, Damn Vulnerable DeFi, real-world audits. 100% detection on top 5 attack types.
