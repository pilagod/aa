// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { IEntryPoint } from "@aa/interfaces/IEntryPoint.sol";
import { UserOperation } from "@aa/interfaces/UserOperation.sol";

import { Initializable } from "@oz/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@oz/proxy/utils/UUPSUpgradeable.sol";

import { SelfAuth } from "./base/SelfAuth.sol";
import { ValidatorManager } from "./base/ValidatorManager.sol";
import { IValidator } from "./interfaces/IValidator.sol";
import { Executor } from "./libraries/Executor.sol";

contract AAWallet is
    Initializable,
    UUPSUpgradeable,
    SelfAuth,
    ValidatorManager
{
    IEntryPoint public immutable entryPoint;

    IValidator public ownerValidator;

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    function initialize(
        IValidator _ownerValidator,
        bytes calldata _ownerValidatorInitData
    ) external initializer {
        ownerValidator = _ownerValidator;
        _addValidator(_ownerValidator, _ownerValidatorInitData);
    }

    receive() external payable { }

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint));
        _;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        IValidator validator = _getValidator(userOp);
        validationData = validator.validateUserOp(userOp, userOpHash);
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: gasleft()
            }("");
            // ignore failure (its EntryPoint's job to verify, not account.)
            (success);
        }
    }

    function _getValidator(UserOperation calldata userOp)
        internal
        view
        returns (IValidator)
    {
        bytes4 selector = bytes4(userOp.callData[:4]);
        if (selector == AAWallet.execute.selector) {
            address to = abi.decode(userOp.callData[4:], (address));
            if (to == address(this)) {
                return ownerValidator;
            }
            if (validators[to]) {
                return ownerValidator;
            }
            address validator = address(bytes20(userOp.signature[:20]));
            if (validators[validator]) {
                return IValidator(validator);
            }
        }
        return ownerValidator;
    }

    function execute(
        address to,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        Executor.call(to, value, data);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        virtual
        override
        onlySelf
    { }
}
