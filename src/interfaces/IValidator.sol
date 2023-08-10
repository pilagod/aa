// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";

import { Severity } from "src/libraries/Severity.sol";

// IValidator is just served as an example, not the final specification.
interface IValidator {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        Severity severity
    ) external returns (uint256 validationData);
}
