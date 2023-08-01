// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

abstract contract SelfAuth {
    modifier onlySelf() {
        require(msg.sender == address(this));
        _;
    }
}
