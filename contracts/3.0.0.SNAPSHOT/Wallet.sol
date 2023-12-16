// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Wallet {
    address public owner;
    event Deposit(address sender, uint amount, uint balance);
    event Withdraw(uint amount, uint balance);
    event Transfer(address to, uint amount, uint balance);

    // 檢查是否為Owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Not Owner");
        _;
    }

    // 初始化
    constructor() payable {
        owner = payable(msg.sender);
    }

    // 存款
    function deposit() public payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    // 查詢餘額
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }

    // 取款
    function withdraw(uint amount) public payable onlyOwner {
        payable(msg.sender).transfer(amount);
        emit Withdraw(amount, address(this).balance);
    }

    // 交易給(某人)
    function transferTo(address payable _user, uint amount) public onlyOwner {
        _user.transfer(amount);
        emit Transfer(_user, amount, address(this).balance);
    }
}
