// this is a simple contract that may contain security issues. DO NOT USE THAT IN PRODUCTION
pragma solidity ^0.8.9;

contract CanaryTokenDrop {
    address public canaryAddress;
    uint256 public maximumToClaim;

    event Droped(address claimer, uint256 amount_claimed);

    constructor(address _canary) {
        canaryAddress = _canary;
        maximumToClaim = 10 * (10 ** 18);
    }

    function drop(uint256 _amount) external {
        
    }
}