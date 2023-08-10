// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";

import { IValidator } from "src/interfaces/IValidator.sol";
import { Severity } from "src/libraries/Severity.sol";

contract NullValidator is IValidator {
    function validateUserOp(
        UserOperation calldata, /* userOp */
        bytes32, /* userOpHash */
        Severity /* severity */
    ) external pure returns (uint256 validationData) {
        return 0;
    }
}
