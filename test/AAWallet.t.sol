// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { UserOperation } from "@aa/interfaces/UserOperation.sol";

import { AAWallet } from "src/AAWallet.sol";
import { AAWalletFactory } from "src/AAWalletFactory.sol";
import { OwnerValidator } from "src/validators/OwnerValidator.sol";

import { AATest } from "./utils/AATest.sol";
import { Wallet, WalletLib } from "./utils/Wallet.sol";

contract AAWalletTest is AATest {
    using WalletLib for Wallet;

    OwnerValidator ownerValidator = new OwnerValidator();
    AAWalletFactory walletFactory =
        new AAWalletFactory(entryPoint, ownerValidator);

    Wallet owner = WalletLib.createRandomWallet(vm);
    AAWallet wallet = walletFactory.createAccount(owner.addr(), 0x1234);

    function setUp() public {
        vm.deal(address(wallet), 1 ether);
    }

    function testSetUp() public {
        assertEq(address(wallet).balance, 1 ether);
        assertEq(ownerValidator.owners(address(wallet)), owner.addr());
    }

    function testTransfer() public {
        Wallet memory recipient = WalletLib.createRandomWallet(vm);

        UserOperation memory userOp = createUserOp();
        userOp.sender = address(wallet);
        userOp.callData = abi.encodeCall(
            AAWallet.execute, (recipient.addr(), 0.1 ether, bytes(""))
        );
        signUserOpEthSignedMessage(owner, userOp);

        handleUserOp(userOp);

        assertEq(recipient.balance(), 0.1 ether);
    }
}
