// this is a simple contract that may contain security issues. DO NOT USE THAT IN PRODUCTION
pragma solidity ^0.8.9;

interface CanaryToken{
    function balanceOf(address _owner) external view returns (uint256 balance);
    function transfer(address _to, uint256 _value) external returns (bool success);
}

contract CanaryTokenDrop {
    CanaryToken canary;
    uint256 public maximumToClaim;

    event Droped(address claimer, uint256 amount_claimed);

    constructor(address _canary) {
        canary = CanaryToken(_canary);
        maximumToClaim = 10 * (10 ** 18);
    }

    function drop(uint256 _amount) external {
        require(canary.balanceOf(address(this)) >= _amount, "not enough to drop");
        uint256 amountToPay = _amount / 5;
        // after transpilation: need to check if the caller has the right amount of STRK to pay for this drop
        // after transpilation: need to send the STRK from the caller account to this drop cotract
        canary.transfer(msg.sender, _amount);
    }
}