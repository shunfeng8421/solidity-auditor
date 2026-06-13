// SPDX-License-Identifier: MIT
// Benchmark: 已知漏洞合约集 (SWC Registry + Real Exploits)
// 每个合约包含一个已知漏洞——用于测试审计引擎的检测率

// ═══════════════════════════════════════════
// SWC-107: Reentrancy (CEI Violation)
// Real: DAO Hack ($60M, 2016), Cream Finance ($130M, 2021)
// ═══════════════════════════════════════════
pragma solidity ^0.8.0;

contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        // VULNERABILITY: state change AFTER external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}

contract ReentrancyFixed {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external noReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}


// ═══════════════════════════════════════════
// SWC-115: tx.origin Authentication
// Real: Numerous phishing attacks
// ═══════════════════════════════════════════
contract TxOriginVulnerable {
    address public owner;

    constructor() { owner = msg.sender; }

    function transferOwnership(address newOwner) external {
        // VULNERABILITY: tx.origin can be phished
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}

contract TxOriginFixed {
    address public owner;

    constructor() { owner = msg.sender; }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
}


// ═══════════════════════════════════════════
// SWC-106: Unprotected SELFDESTRUCT
// Real: Parity Wallet freeze ($280M, 2017)
// ═══════════════════════════════════════════
contract SelfdestructVulnerable {
    address public owner;

    constructor() { owner = msg.sender; }

    function kill() external {
        // VULNERABILITY: anyone can call selfdestruct
        selfdestruct(payable(msg.sender));
    }
}

contract SelfdestructFixed {
    address public owner;

    constructor() { owner = msg.sender; }

    function kill() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }
}


// ═══════════════════════════════════════════
// SWC-101: Integer Overflow (pre-0.8.0)
// Real: BeautyChain ($1B, 2018)
// ═══════════════════════════════════════════
pragma solidity ^0.6.0;

contract OverflowVulnerable {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // VULNERABILITY: no overflow check in Solidity <0.8
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}


// ═══════════════════════════════════════════
// SWC-120: Weak Randomness
// Real: Numerous gambling contract exploits
// ═══════════════════════════════════════════
pragma solidity ^0.8.0;

contract WeakRandomVulnerable {
    function flip() external view returns (bool) {
        // VULNERABILITY: block.timestamp + block.difficulty are predictable
        return uint256(keccak256(abi.encodePacked(
            block.timestamp, block.difficulty, msg.sender
        ))) % 2 == 0;
    }
}


// ═══════════════════════════════════════════
// SWC-104: Unchecked Call Return Value
// Real: King of the Ether (2016)
// ═══════════════════════════════════════════
contract UncheckedSendVulnerable {
    function sendEth(address payable to, uint256 amount) external {
        // VULNERABILITY: .send() returns false on failure, not checked
        to.send(amount);
    }
}


// ═══════════════════════════════════════════
// Oracle Manipulation (Flash Loan)
// Real: Cream Finance $130M, Harvest $34M
// ═══════════════════════════════════════════
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract OracleManipulationVulnerable {
    IUniswapV2Pair public pair;

    constructor(address _pair) { pair = IUniswapV2Pair(_pair); }

    function getPrice() external view returns (uint256) {
        // VULNERABILITY: spot price from AMM, manipulable via flash loan
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }
}


// ═══════════════════════════════════════════
// Unprotected Initializer
// Real: Parity Multisig ($280M, 2017)
// ═══════════════════════════════════════════
contract UnprotectedInitVulnerable {
    bool public initialized;
    address public owner;

    function initialize() external {
        // VULNERABILITY: anyone can call initialize()
        require(!initialized);
        owner = msg.sender;
        initialized = true;
    }
}


// ═══════════════════════════════════════════
// ERC20 approve Race Condition
// ═══════════════════════════════════════════
contract ApproveRaceVulnerable {
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        // VULNERABILITY: approve() can be front-run (first set to 0, wait for tx, set to N)
        allowance[msg.sender][spender] = amount;
        return true;
    }
}


// ═══════════════════════════════════════════
// Missing Slippage Protection
// Real: MEV sandwich attacks (daily millions)
// ═══════════════════════════════════════════
contract SwapNoSlippageVulnerable {
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        // VULNERABILITY: no minAmountOut — sandwich attack possible
        IUniswapV2Pair(tokenIn).swap(0, amountIn, address(this), "");
    }
}
