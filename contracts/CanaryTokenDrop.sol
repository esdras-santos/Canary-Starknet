// this is a simple contract that may contain security issues. DO NOT USE THAT IN PRODUCTION
pragma solidity ^0.8.9;

interface Token{
    function balanceOf(address _owner) external view returns (uint256 balance);
    function transfer(address _to, uint256 _value) external returns (bool success);
}

contract CanaryTokenDrop {
    Token canary;
    uint256 public maximumToClaim;

    event Droped(address claimer, uint256 amount_claimed);

    constructor(address _canary) {
        canary = Token(_canary);
        maximumToClaim = 10 * (10 ** 18);
    }

    function drop(uint256 _amount) external {
        require(canary.balanceOf(address(this)) >= _amount, "not enough to drop");
        require(_amount <= maximumToClaim, "cannot claim more than 10 CanaryTokens");
        //uint256 amountToPay = _amount / 5;
        //require(msg.sender.balance >= amountToPay);
        canary.transfer(msg.sender, _amount);
    }
}