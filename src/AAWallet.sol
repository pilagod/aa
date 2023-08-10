// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { IEntryPoint } from "@aa/interfaces/IEntryPoint.sol";
import { UserOperation } from "@aa/interfaces/UserOperation.sol";

import { Initializable } from "@oz/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@oz/proxy/utils/UUPSUpgradeable.sol";

import { PluginManager } from "./base/PluginManager.sol";
import { SelfAuth } from "./base/SelfAuth.sol";
import { ValidatorManager } from "./base/ValidatorManager.sol";
import { IValidator } from "./interfaces/IValidator.sol";
import { Executor } from "./libraries/Executor.sol";
import { Severity } from "./libraries/Severity.sol";

contract AAWallet is
    Initializable,
    UUPSUpgradeable,
    SelfAuth,
    ValidatorManager,
    PluginManager
{
    IEntryPoint public immutable entryPoint;

    IValidator public ownerValidator;

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    receive() external payable { }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint));
        _;
    }

    function initialize(
        IValidator _ownerValidator,
        bytes calldata _ownerValidatorInitData
    ) external initializer {
        ownerValidator = _ownerValidator;
        _addValidator(_ownerValidator, _ownerValidatorInitData);
    }

    function setOwnerValidator(
        IValidator _ownerValidator,
        bytes calldata _ownerValidatorInitData
    ) external onlySelf {
        IValidator prevOwnerValidator = ownerValidator;
        ownerValidator = _ownerValidator;
        _addValidator(_ownerValidator, _ownerValidatorInitData);
        // Remove previous owner validator to avoid executing wallet by outdated validation mechanism.
        _removeValidator(prevOwnerValidator);
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        (IValidator validator, Severity severity) = _getValidationInfo(userOp);
        validationData = validator.validateUserOp(userOp, userOpHash, severity);

        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: gasleft()
            }("");
            // ignore failure (its EntryPoint's job to verify, not account.)
            (success);
        }
    }

    function _getValidationInfo(UserOperation calldata userOp)
        internal
        view
        returns (IValidator, Severity)
    {
        bytes4 selector = bytes4(userOp.callData[:4]);

        if (selector == AAWallet.execute.selector) {
            (address to,, bytes memory callData) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            // If execution target is account itself or validator,
            // the call requires to be validated by owner validator.
            if (to == address(this)) {
                return (ownerValidator, _parseSeverity(callData));
            }
            if (validators[to]) {
                return (ownerValidator, Severity.High);
            }
            // Allow custom validator when not calling to account itself.
            address validator = address(bytes20(userOp.signature[:20]));
            if (validators[validator]) {
                return (IValidator(validator), Severity.Low);
            }
            // If custom validator is not valid, fallback to owner validator.
            return (ownerValidator, Severity.Low);
        }

        if (selector == AAWallet.executeBatch.selector) {
            (address[] memory to,, bytes[] memory callData) =
                abi.decode(userOp.callData[4:], (address[], uint256[], bytes[]));
            bool callSelf = false;
            for (uint256 i = 0; i < to.length; i++) {
                // If at least one execution target is account itself or validator,
                // the call requires to be validated by owner validator.
                if (to[i] == address(this)) {
                    if (_parseSeverity(callData[i]) == Severity.High) {
                        return (ownerValidator, Severity.High);
                    }
                    callSelf = true;
                }
                if (validators[to[i]]) {
                    return (ownerValidator, Severity.High);
                }
            }
            if (callSelf) {
                return (ownerValidator, Severity.Low);
            }
            // Allow custom validator when not calling to account itself.
            address validator = address(bytes20(userOp.signature[:20]));
            if (validators[validator]) {
                return (IValidator(validator), Severity.Low);
            }
            // If custom validator is not valid, fallback to owner validator.
            return (ownerValidator, Severity.Low);
        }

        // For other functions on wallet, it must require validated by owner validator.
        return (ownerValidator, _parseSeverity(userOp.callData));
    }

    function execute(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        Executor.call(to, value, data);
    }

    function executeBatch(
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data
    ) external onlyEntryPoint {
        require(
            to.length == value.length && to.length == data.length,
            "wrong array lengths"
        );
        for (uint256 i = 0; i < to.length; i++) {
            Executor.call(to[i], value[i], data[i]);
        }
    }

    // Serve as an example function for low severity
    function lock() external onlySelf { }

    function _authorizeUpgrade(address newImplementation)
        internal
        virtual
        override
        onlySelf
    { }

    function _parseSeverity(bytes memory callData)
        internal
        pure
        returns (Severity)
    {
        bytes4 selector = bytes4(callData);
        if (selector == AAWallet.lock.selector) {
            return Severity.Low;
        }
        return Severity.High;
    }
}
