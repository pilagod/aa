// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";
import { ECDSA } from "@oz/utils/cryptography/ECDSA.sol";

import { IValidator } from "src/interfaces/IValidator.sol";
import { IValidatorManager } from "src/interfaces/IValidatorManager.sol";
import { Severity } from "src/libraries/Severity.sol";

contract OwnerValidator is IValidator {
    error ValidatorUnauthorized();

    using ECDSA for bytes32;

    modifier whenValidatorAuthorized() {
        // Skip for initialize phase
        if (msg.sender.code.length > 0) {
            if (
                !IValidatorManager(msg.sender).isValidatorAuthorized(
                    address(this)
                )
            ) {
                revert ValidatorUnauthorized();
            }
        }
        _;
    }

    mapping(address => address) public owners;
    mapping(address => address) public guardians;

    function setOwner(address owner) external whenValidatorAuthorized {
        owners[msg.sender] = owner;
    }

    function setGuardian(address guardian) external whenValidatorAuthorized {
        guardians[msg.sender] = guardian;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        Severity severity
    ) external view whenValidatorAuthorized returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);
        // Owner can authorize for operation with every severity.
        if (signer == owners[msg.sender]) {
            return 0;
        }
        // Allow guardian to authorize operation with low severity
        if (severity == Severity.Low) {
            if (signer == guardians[msg.sender]) {
                return 0;
            }
        }
        return 1;
    }
}
