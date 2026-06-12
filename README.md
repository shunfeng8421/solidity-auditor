# Solidity Auditor v3

**Solidity 智能合约自动化安全审计引擎 — 75+ 检查, 100 分制**

对标 Hermes Skill Auditor 架构，面向 Web3 安全审计。

## Quick Start

```bash
# 单文件
python auditor_v3.py --path contract.sol

# 目录批量
python auditor_v3.py --dir contracts/

# 基础检查 (25 规则, 极快)
python auditor.py --dir contracts/
```

## 三层检测

| 层 | 内容 | 检测数 |
|----|------|--------|
| 基础规则 | reentrancy, access control, arithmetic | 25 |
| DeFi 规则 | flashloan, MEV, governance, oracle | 25 |
| 深度检查 | CEI pattern, 25 vulnerability signatures | 25+ |

## 验证

```
Uniswap V4: 84 contracts, 210 findings (21 critical, 148 high)
Known reentrancy test: detected 8 findings including CEI violation
```

## 评分

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90+ | Production-ready |
| B | 70-89 | Minor issues |
| C | 50-69 | Needs improvement |
| D | <50 | Critical issues |

## 相关项目

- [Hermes Skill Auditor](https://github.com/shunfeng8421/hermes-skill-auditor) — 同架构，面向 Hermes 技能
- [Solidity Auditor v3 — Full Report (Uniswap V4)](output/uni_v3.json)

## License

MIT
