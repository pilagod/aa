// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";
import { ECDSA } from "@oz/utils/cryptography/ECDSA.sol";

import { IValidator } from "./IValidator.sol";

contract OwnerValidator is IValidator {
    using ECDSA for bytes32;

    mapping(address => address) public owners;

    function setOwner(address owner) external {
        owners[msg.sender] = owner;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external view returns (uint256 validationData) {
        address owner = owners[msg.sender];
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature)) {
            return 1;
        }
        return 0;
    }
}
