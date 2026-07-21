// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IExecutor} from "./interfaces/IExecutor.sol";
import {IHook} from "./interfaces/IHook.sol";
import {IStorage} from "./interfaces/IStorage.sol";
import {WalletCoreBase} from "./base/WalletCoreBase.sol";
import {WalletCoreLib} from "./lib/WalletCoreLib.sol";
import {Call, Session} from "./Types.sol";
import {Errors} from "./lib/Errors.sol";

abstract contract ExecutorLogic is IExecutor, WalletCoreBase {
    bytes32 public constant SESSION_TYPEHASH =
        keccak256(
            "Session(address wallet,uint256 id,address executor,address validator,uint256 validUntil,uint256 validAfter,bytes preHook,bytes postHook)"
        );

    /**
     * @notice Restricts function access to the authorized executor with a valid session and executes hooks
     * @dev Performs two checks:
     *      1. Caller must match the session's executor
     *      2. Session must be valid (not expired, not invalidated)
     * @dev Hook address is extracted from first 20 bytes of hook data
     * @dev Remaining bytes are passed as hook parameters
     * @param session The session data containing executor permissions and hook configurations
     * @param calls Array of calls to be executed
     * @custom:hooks PreHook runs before execution, PostHook runs after with preHook return data
     */
    modifier onlyValidSession(Session calldata session, Call[] calldata calls) {
        validateSession(session);
        bytes memory ret;
        if (session.preHook.length >= 20)
            ret = IHook(address(bytes20(session.preHook[:20]))).preCheck(
                calls,
                session.preHook[20:],
                msg.sender
            );
        _;
        if (session.postHook.length >= 20)
            IHook(address(bytes20(session.postHook[:20]))).postCheck(
                ret,
                session.postHook[20:],
                msg.sender
            );
    }

    /**
     * @notice Validates a session's time bounds, status, and signature
     * @dev Checks three conditions:
     *      1. Current time is within session's time bounds
     *      2. Session is not invalidated in storage
     *      3. Session signature is valid using specified validator
     * @param session The session data to validate
     */
    function validateSession(Session calldata session) public view {
        // Check executor authorization
        if (msg.sender != session.executor) revert Errors.InvalidExecutor();

        // Check time bounds
        if (
            session.validAfter > block.timestamp ||
            block.timestamp > session.validUntil
        ) revert Errors.InvalidSession();

        // Check invalidSessionId & validValidator in storage
        getMainStorage().validateSession(session.id, session.validator);

        // Validate signature
        bytes32 hash = getSessionTypedHash(session);
        bool isValid = WalletCoreLib.validate(
            session.validator,
            hash,
            session.signature
        );
        if (!isValid) revert Errors.InvalidSignature();
    }

    /**
     * @notice Creates an EIP-712 typed data hash for session validation
     * @dev Combines session data with domain separator using EIP-712 standard
     * @param session The session data containing ID, executor, validator, time bounds, and hooks
     * @return bytes32 The EIP-712 compliant hash for signature verification
     */
    function getSessionTypedHash(
        Session calldata session
    ) public view returns (bytes32) {
        return hashTypedDataV4(getSessionHash(session));
    }

    /**
     * @notice Creates a hash of session parameters for EIP-712 struct hashing
     * @dev Packs session data with SESSION_TYPEHASH using keccak256
     * @param session Session data
     * @return bytes32 The packed and hashed session data
     */
    function _getSessionHash(
        Session calldata session
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    SESSION_TYPEHASH,
                    _walletImplementation(),
                    session.id,
                    session.executor,
                    session.validator,
                    session.validUntil,
                    session.validAfter,
                    keccak256(session.preHook),
                    keccak256(session.postHook)
                )
            );
    }
}
