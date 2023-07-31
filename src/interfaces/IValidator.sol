// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";

interface IValidator {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData);
}
