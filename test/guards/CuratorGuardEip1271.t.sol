// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {Safe} from "safe-contracts-v1.4.1/contracts/Safe.sol";
import {SafeProxy} from "safe-contracts-v1.4.1/contracts/proxies/SafeProxy.sol";
import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardHarness, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";
import {SafeTxHelper} from "test/guards/SafeTxHelper.sol";

/// @dev USDC-shaped token: `permit` accepts EIP-1271 signatures when `owner` is a contract
///      (mainnet `FiatTokenV2_2` does the same for `permit` and EIP-3009 `transferWithAuthorization`).
contract MockPermitToken is ERC20 {
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;

    constructor() ERC20("Mock USDC", "mUSDC") {}

    function mint(address to_, uint256 amount_) external {
        _mint(to_, amount_);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                    keccak256("Mock USDC"),
                    block.chainid,
                    address(this)
                )
            );
    }

    function permitDigest(address owner_, address spender_, uint256 value_, uint256 deadline_) public view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender_, value_, nonces[owner_], deadline_))
                )
            );
    }

    function permit(address owner_, address spender_, uint256 value_, uint256 deadline_, bytes calldata signature_) external {
        require(block.timestamp <= deadline_, "permit expired");
        bytes32 _digest = permitDigest(owner_, spender_, value_, deadline_);
        require(SignatureChecker.isValidSignatureNow(owner_, _digest, signature_), "invalid signature");
        ++nonces[owner_];
        _approve(owner_, spender_, value_);
    }
}

/// @title EIP-1271 drain path and the required-fallback-handler policy (real Safe v1.4.1 + handler)
/// @notice With the canonical `CompatibilityFallbackHandler` installed, a signer quorum can authorise
///         a `permit` off-chain and drain a 1271-aware token with no Safe transaction at all: the
///         guard is never consulted. `setRequiredFallbackHandler(safe, address(0), true)` makes the
///         policy refuse to run until that handler is gone, which closes the path.
contract CuratorGuardEip1271Test is SafeTxHelper {
    CuratorGuard internal guard;
    CompatibilityFallbackHandler internal handler;
    MockPermitToken internal token;
    MockProtocol internal protocol;

    address internal vetro = makeAddr("vetro");


    address internal council = makeAddr("council");
    address internal attacker = makeAddr("attacker");
    address internal curator;

    uint256 internal constant BALANCE = 1_000_000e6;

    function setUp() public {
        vm.warp(1_700_000_000); // a realistic time: Foundry's default timestamp of 1 sits inside the lockdown cooldown
        (curator, signerPk) = makeAddrAndKey("curator");
        Safe _singleton = new Safe();
        SafeProxy _proxy = new SafeProxy(address(_singleton));
        handler = new CompatibilityFallbackHandler();
        address[] memory _owners = new address[](1);
        _owners[0] = curator;
        Safe(payable(address(_proxy))).setup(_owners, 1, address(0), "", address(handler), address(0), 0, payable(address(0)));
        safe = ISafe(address(_proxy));

        token = new MockPermitToken();
        token.mint(address(safe), BALANCE);
        protocol = new MockProtocol();
        guard = new CuratorGuardHarness(0, vetro, council);
        CuratorGuardHarness(address(guard)).seedSafe(address(safe)); // locally compiled Safe build: seeded, the guard pins canonical Safe code (V2-85)
        _execSafeTx(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(guard))), Operation.Call);

        vm.startPrank(vetro);
        guard.enforce(address(safe));
        guard.allowFunction(address(safe), address(protocol), MockProtocol.settleDeposit.selector, false, _noRules());
        vm.stopPrank();
    }

    function test_eip1271_permit_drain_bypasses_the_guard_while_the_handler_is_installed() public {
        uint256 _deadline = block.timestamp + 1 hours;
        bytes memory _signature = _safeMessageSignature(token.permitDigest(address(safe), attacker, type(uint256).max, _deadline));
        uint256 _nonceBefore = safe.nonce();

        vm.startPrank(attacker);
        token.permit(address(safe), attacker, type(uint256).max, _deadline, _signature);
        token.transferFrom(address(safe), attacker, BALANCE);
        vm.stopPrank();

        assertEq(token.balanceOf(attacker), BALANCE, "drained with zero Safe transactions");
        assertEq(safe.nonce(), _nonceBefore, "guard never consulted");
    }

    function test_required_fallback_handler_freezes_the_policy_until_the_handler_is_removed() public {
        vm.prank(vetro);
        guard.setRequiredFallbackHandler(address(safe), address(0), true);
        bytes memory _settle = abi.encodeCall(MockProtocol.settleDeposit, (1));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FallbackHandlerNotAllowed.selector, address(handler)));
        _execSafeTx(address(protocol), 0, _settle, Operation.Call);

        bytes memory _remove = abi.encodeWithSignature("setFallbackHandler(address)", address(0));
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), address(safe), 0, _remove, Operation.Call, uint64(1 days));
        assertTrue(_execSafeTx(address(safe), 0, _remove, Operation.Call));
        assertTrue(_execSafeTx(address(protocol), 0, _settle, Operation.Call));

        // The Safe no longer answers isValidSignature: the off-chain permit path is closed.
        uint256 _deadline = block.timestamp + 1 hours;
        bytes memory _signature = _safeMessageSignature(token.permitDigest(address(safe), attacker, type(uint256).max, _deadline));
        vm.prank(attacker);
        vm.expectRevert(bytes("invalid signature"));
        token.permit(address(safe), attacker, type(uint256).max, _deadline, _signature);
        assertEq(token.balanceOf(address(safe)), BALANCE);
    }

    function test_curator_cannot_reinstall_a_handler_through_the_policy() public {
        bytes memory _set = abi.encodeWithSignature("setFallbackHandler(address)", address(handler));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(keccak256("setFallbackHandler(address)"))));
        _execSafeTx(address(safe), 0, _set, Operation.Call);
    }

    /// @dev Signs `digest_` the way a Safe owner signs any EIP-1271 message: the Safe-wrapped hash.
    function _safeMessageSignature(bytes32 digest_) internal view returns (bytes memory) {
        return _sign(handler.getMessageHashForSafe(Safe(payable(address(safe))), abi.encode(digest_)));
    }

    function _noRules() internal pure returns (CuratorGuardPolicy.ParamRule[] memory _rules) {}
}
