// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {MultiSendCallOnly} from "safe-contracts-v1.4.1/contracts/libraries/MultiSendCallOnly.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {ISafeTransactionGuard, ISafeModuleGuard, Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase, MockProtocol} from "test/guards/CuratorGuardTestBase.sol";

/// @dev An abicoder-v2 callee (solc 0.8.25): what a venue DECODES from the bytes the guard checked.
contract G10bVenue {
    struct Pair {
        address token;
        uint256 amount;
    }

    bytes public lastPayload;
    uint256 public lastN;
    address public lastWho;
    uint256 public lastSum;
    address public lastSender;

    /// @dev `(uint256 n, bytes p)`: the first dynamic parameter is word 1.
    function run(uint256 n_, bytes calldata p_) external {
        lastN = n_;
        lastPayload = p_;
    }

    /// @dev A static struct is inlined in the head (docs section 5, the Morpho example): `who` is word 2.
    function pair(Pair calldata p_, address who_) external {
        lastSum = p_.amount;
        lastWho = who_;
    }

    /// @dev A static fixed-size array is inlined too: `who` is word 2.
    function arr(uint256[2] calldata a_, address who_) external {
        lastSum = a_[0] + a_[1];
        lastWho = who_;
    }

    /// @dev A dynamic array of static structs is one offset word: the whole array is in the tail from word 0.
    function many(Pair[] calldata ps_) external {
        uint256 _sum;
        for (uint256 i; i < ps_.length; ++i) _sum += ps_[i].amount;
        lastSum = _sum;
    }

    fallback() external payable {
        lastSender = msg.sender;
    }
}

/// @title Round 10 (g10b): calldata and ABI edges, deterministic.
contract G10bAbiEdgesTest is CuratorGuardTestBase {
    G10bVenue internal venue;
    uint16 internal constant TAIL = 0x8000;

    function setUp() public override {
        super.setUp();
        venue = new G10bVenue();
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
        G10b-1: A NON-CANONICAL REVIEWED TAIL BINDS BYTES, NOT MEANING
    //////////////////////////////////////////////////////////////*/

    /// @dev Section 5 says a tail rule from the FIRST dynamic parameter's head word binds a dynamic payload
    ///      exactly, "the static words before it keep their own rules". A static word without a rule (the lint
    ///      only warns for unbound ADDRESS words) is still read by the callee, and when the reviewed payload is
    ///      not canonical its offset can point back INTO that unbound word: the hash pins every byte from word 1
    ///      on, yet the venue decodes a different `p` for every `n`. The reviewed payload is the signers' own
    ///      calldata (section 5: "compute it from the exact calldata the signers will send"), so the signers
    ///      choose its encoding; a decoder-based review (Safe{Wallet}, `cast 4byte-decode`) shows the meaning,
    ///      not the offset.
    function test_G10b1_backward_offset_in_a_reviewed_tail_lets_an_unbound_static_word_change_the_payload() public {
        // The reviewed tail from word 1: offset 0x00 (pointing at word 0, i.e. `n` is read as the length), then
        // 64 bytes of payload. Canonical would be offset 0x40.
        bytes memory _tail = abi.encodePacked(uint256(0), bytes32(hex"aa"), bytes32(hex"bb"));
        CuratorGuardPolicy.ParamRule[] memory _rules = _rule(CuratorGuardPolicy.RuleKind.EqualTo, 1 | TAIL, keccak256(_tail));
        _allowWithRules(address(venue), G10bVenue.run.selector, _rules);

        // n = 0: the venue decodes an EMPTY payload.
        bytes memory _call0 = abi.encodePacked(G10bVenue.run.selector, uint256(0), _tail);
        assertTrue(_execSafeTx(address(venue), 0, _call0, Operation.Call), "n = 0 accepted");
        assertEq(venue.lastPayload().length, 0, "n = 0 decodes an empty payload");

        // n = 64: the same pinned tail, and the venue now decodes 64 bytes: the offset word (zeros) and 0xaa...
        bytes memory _call64 = abi.encodePacked(G10bVenue.run.selector, uint256(64), _tail);
        assertTrue(_execSafeTx(address(venue), 0, _call64, Operation.Call), "n = 64 accepted");
        assertEq(venue.lastPayload(), abi.encodePacked(uint256(0), bytes32(hex"aa")), "n = 64 decodes 64 bytes of the pinned tail");

        // n = 32: 32 bytes (the zero offset word).
        bytes memory _call32 = abi.encodePacked(G10bVenue.run.selector, uint256(32), _tail);
        assertTrue(_execSafeTx(address(venue), 0, _call32, Operation.Call), "n = 32 accepted");
        assertEq(venue.lastPayload(), abi.encodePacked(uint256(0)), "n = 32 decodes the offset word");

        // The hash is byte-exact: the canonical encoding of the SAME logical call is refused (as documented).
        bytes memory _canonical = abi.encodeCall(G10bVenue.run, (0, abi.encodePacked(bytes32(hex"aa"), bytes32(hex"bb"))));
        vm.expectRevert(
            abi.encodeWithSelector(
                CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.run.selector, uint16(1 | TAIL), keccak256(_sliceFrom(_canonical, 36))
            )
        );
        _execSafeTx(address(venue), 0, _canonical, Operation.Call);
    }

    /// @dev With a CANONICAL reviewed tail every offset points into the hashed region: the unbound static
    ///      word changes nothing the callee reads as `p`. This is the property section 5 promises, and the
    ///      lint can enforce it on the raw tail bytes it is given (fix G10b-1).
    function test_canonical_reviewed_tail_keeps_the_payload_whatever_the_unbound_word_says() public {
        bytes memory _p = abi.encodePacked(bytes32(hex"aa"), bytes32(hex"bb"));
        bytes memory _tail = _sliceFrom(abi.encodeCall(G10bVenue.run, (0, _p)), 36); // from word 1
        CuratorGuardPolicy.ParamRule[] memory _rules = _rule(CuratorGuardPolicy.RuleKind.EqualTo, 1 | TAIL, keccak256(_tail));
        _allowWithRules(address(venue), G10bVenue.run.selector, _rules);
        uint256[4] memory _ns = [uint256(0), 32, 64, type(uint256).max];
        for (uint256 i; i < 4; ++i) {
            assertTrue(_execSafeTx(address(venue), 0, abi.encodePacked(G10bVenue.run.selector, _ns[i], _tail), Operation.Call));
            assertEq(venue.lastPayload(), _p, "payload independent of n");
            assertEq(venue.lastN(), _ns[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                 HEAD INDEXING AGAINST A REAL ABICODER-V2 CALLEE
    //////////////////////////////////////////////////////////////*/

    /// @dev Docs section 5: a static struct is inlined, so `pair((token, amount), who)` has `who` at word 2;
    ///      the same for a static fixed-size array. `EqualToSafe` on word 2 refuses a foreign receiver.
    function test_inlined_struct_and_fixed_array_words_are_what_the_callee_decodes() public {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 1, bytes32(uint256(100)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, 2, 0);
        _allowWithRules(address(venue), G10bVenue.pair.selector, _rules);
        _allowWithRules(address(venue), G10bVenue.arr.selector, _rules);

        G10bVenue.Pair memory _p = G10bVenue.Pair(address(token), 100);
        assertTrue(_execSafeTx(address(venue), 0, abi.encodeCall(G10bVenue.pair, (_p, address(safe))), Operation.Call));
        assertEq(venue.lastWho(), address(safe));
        assertEq(venue.lastSum(), 100);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.pair.selector, uint16(2), _word(attacker)));
        _execSafeTx(address(venue), 0, abi.encodeCall(G10bVenue.pair, (_p, attacker)), Operation.Call);
        _p.amount = 101;
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.pair.selector, uint16(1), bytes32(uint256(101))));
        _execSafeTx(address(venue), 0, abi.encodeCall(G10bVenue.pair, (_p, address(safe))), Operation.Call);

        uint256[2] memory _a = [uint256(60), 40];
        assertTrue(_execSafeTx(address(venue), 0, abi.encodeCall(G10bVenue.arr, (_a, address(safe))), Operation.Call));
        assertEq(venue.lastWho(), address(safe));
        assertEq(venue.lastSum(), 100);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.arr.selector, uint16(2), _word(attacker)));
        _execSafeTx(address(venue), 0, abi.encodeCall(G10bVenue.arr, (_a, attacker)), Operation.Call);
    }

    /// @dev A dynamic array of static structs is one offset word: a tail rule from word 0 pins the whole array
    ///      (count, every member) and any other array, re-encoded or not, is refused.
    function test_dynamic_array_of_structs_is_one_offset_word_bound_by_a_tail_rule() public {
        G10bVenue.Pair[] memory _ps = new G10bVenue.Pair[](2);
        _ps[0] = G10bVenue.Pair(address(token), 1);
        _ps[1] = G10bVenue.Pair(address(token), 2);
        bytes memory _call = abi.encodeCall(G10bVenue.many, (_ps));
        _allowWithRules(address(venue), G10bVenue.many.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0 | TAIL, keccak256(_sliceFrom(_call, 4))));
        assertTrue(_execSafeTx(address(venue), 0, _call, Operation.Call));
        assertEq(venue.lastSum(), 3);
        _ps[1].amount = 3;
        bytes memory _other = abi.encodeCall(G10bVenue.many, (_ps));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.many.selector, uint16(0 | TAIL), keccak256(_sliceFrom(_other, 4))));
        _execSafeTx(address(venue), 0, _other, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                         TAIL SCOPE INSIDE A BATCH
    //////////////////////////////////////////////////////////////*/

    /// @dev Inside a batch the tail hash runs to the END OF THE ENTRY (its declared data length), never into
    ///      the next entry or the batch's padding: an entry equal to the reviewed calldata passes next to any
    ///      other entry, and one extra byte inside the entry is refused.
    function test_tail_rule_inside_a_batch_entry_hashes_to_the_entry_end() public {
        bytes memory _p = hex"beef";
        bytes memory _call = abi.encodeCall(G10bVenue.run, (7, _p));
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 0, bytes32(uint256(7)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, 1 | TAIL, keccak256(_sliceFrom(_call, 36)));
        _allowWithRules(address(venue), G10bVenue.run.selector, _rules);
        _allow(address(protocol), MockProtocol.settleDeposit.selector);

        bytes memory _next = abi.encodeCall(MockProtocol.settleDeposit, (1));
        bytes memory _batch = _multiSendCalldata(abi.encodePacked(_entry(address(venue), 0, _call), _entry(address(protocol), 0, _next)));
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall), "entry then another entry");
        assertEq(venue.lastPayload(), _p);
        assertEq(protocol.lastAmount(), 1);

        bytes memory _longer = abi.encodePacked(_call, hex"00");
        _batch = _multiSendCalldata(abi.encodePacked(_entry(address(venue), 0, _longer), _entry(address(protocol), 0, _next)));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G10bVenue.run.selector, uint16(1 | TAIL), keccak256(_sliceFrom(_longer, 36)))
        );
        _execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
    }

    /*//////////////////////////////////////////////////////////////
                  NESTED BATCHES AND THE UNWRAPPER REGISTRY
    //////////////////////////////////////////////////////////////*/

    /// @dev A `multiSend` entry addressed to the registered unwrapper as a PLAIN call is an ordinary venue call
    ///      (`FunctionNotAllowed` on the policy path). Inside a council window it runs, but from the LIBRARY's
    ///      address: its inner entries reach the Safe as a stranger, so a nested `setGuard` is `GS031`, and the
    ///      window's self-call limits are not escaped.
    function test_nested_plain_call_multiSend_runs_from_the_library_not_the_safe() public {
        bytes memory _inner = _multiSendCalldata(_entry(address(safe), 0, abi.encodeCall(ISafe.setGuard, (address(0)))));
        bytes memory _outer = _multiSendCalldata(_entry(address(multiSendCallOnly), 0, _inner));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.FunctionNotAllowed.selector, address(multiSendCallOnly), bytes4(0x8d80ff0a)));
        _execSafeTx(address(multiSendCallOnly), 0, _outer, Operation.DelegateCall);

        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        // The nested library call reverts (the Safe refuses `setGuard` from a stranger), so the whole batch fails.
        vm.expectRevert(bytes("GS013"));
        _execSafeTx(address(multiSendCallOnly), 0, _outer, Operation.DelegateCall);
        assertEq(_installedGuard(), address(guard), "guard still installed");

        // A harmless nested batch shows the sender the inner entries see: the library, not the Safe.
        _inner = _multiSendCalldata(_entry(address(venue), 0, hex"01020304"));
        _outer = _multiSendCalldata(_entry(address(multiSendCallOnly), 0, _inner));
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _outer, Operation.DelegateCall));
        assertEq(venue.lastSender(), address(multiSendCallOnly), "inner entries run from the library");
    }

    /// @dev Any deployment of the canonical bytecode is registrable (same runtime hash); a build with the same
    ///      hash that was never registered for this Safe is still `DelegateCallNotAllowed`.
    function test_a_second_deployment_of_the_same_code_is_registrable_but_not_registered_by_itself() public {
        MultiSendCallOnly _copy = new MultiSendCallOnly();
        assertEq(address(_copy).codehash, address(multiSendCallOnly).codehash, "same runtime code");
        _allow(address(protocol), MockProtocol.settleDeposit.selector);
        bytes memory _batch = _multiSendCalldata(_entry(address(protocol), 0, abi.encodeCall(MockProtocol.settleDeposit, (1))));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.DelegateCallNotAllowed.selector, address(_copy)));
        _execSafeTx(address(_copy), 0, _batch, Operation.DelegateCall);
        vm.prank(vetro);
        guard.setMultiSendUnwrapper(address(safe), address(_copy), true);
        assertTrue(_execSafeTx(address(_copy), 0, _batch, Operation.DelegateCall));
    }

    /*//////////////////////////////////////////////////////////////
                          SHORT DATA AND ERC-165
    //////////////////////////////////////////////////////////////*/

    /// @dev Selector extraction on 1 to 3 bytes: `bytes4(0)` in every typed refusal, and `MalformedCalldata` for a
    ///      venue, on the owner and module paths alike; a council window lets a 1-to-3-byte venue call through
    ///      and the library hands exactly those bytes to the venue.
    function test_short_data_is_typed_per_target_class_and_executes_only_inside_a_window() public {
        bytes memory _three = hex"010203";
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(safe), 0, _three, Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.GuardCallNotAllowed.selector, bytes4(0)));
        _execSafeTx(address(guard), 0, _three, Operation.Call);
        vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
        _execSafeTx(address(venue), 0, _three, Operation.Call);
        // module path: the module allowlist is read first, then the same typed refusal
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.ModuleNotAllowed.selector, address(0xBEEF)));
        guard.validateModuleTransaction(address(safe), address(0xBEEF), address(venue), 0, _three, Operation.Call);
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), address(0xBEEF), true);
        vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
        guard.validateModuleTransaction(address(safe), address(0xBEEF), address(venue), 0, _three, Operation.Call);

        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _multiSendCalldata(_entry(address(venue), 0, _three)), Operation.DelegateCall));
        assertEq(venue.lastSender(), address(safe));
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.CouncilBypassLimit.selector, bytes4(0)));
        _execSafeTx(address(safe), 0, _three, Operation.Call);
    }

    function test_erc165_surface() public view {
        assertTrue(guard.supportsInterface(type(ISafeTransactionGuard).interfaceId));
        assertTrue(guard.supportsInterface(type(ISafeModuleGuard).interfaceId));
        assertEq(type(ISafeTransactionGuard).interfaceId, bytes4(0xe6d7a83a));
        assertEq(type(ISafeModuleGuard).interfaceId, bytes4(0x58401ed8));
        assertTrue(guard.supportsInterface(0x01ffc9a7)); // ERC-165 itself
        assertTrue(guard.supportsInterface(0x7965db0b)); // IAccessControl
        assertFalse(guard.supportsInterface(0xffffffff));
        assertFalse(guard.supportsInterface(0x8d80ff0a));
    }

    function _sliceFrom(bytes memory b_, uint256 start_) internal pure returns (bytes memory _out) {
        _out = new bytes(b_.length - start_);
        for (uint256 i; i < _out.length; ++i) _out[i] = b_[start_ + i];
    }
}
