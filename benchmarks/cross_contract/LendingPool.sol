pragma solidity ^0.8.0;
interface IPriceOracle { function getPrice() external view returns (uint256); }
contract LendingPool {
    IPriceOracle public oracle;
    mapping(address=>uint256) public collateral;
    mapping(address=>uint256) public debt;
    constructor(address _oracle) { oracle = IPriceOracle(_oracle); }
    function borrow(uint256 amount) external {
        uint256 price = oracle.getPrice();
        uint256 maxBorrow = (collateral[msg.sender]*price)/1e18;
        require(amount <= maxBorrow, "Insufficient collateral");
        debt[msg.sender] += amount;
    }
    function addCollateral(uint256 amount) external { collateral[msg.sender]+=amount; }
}
