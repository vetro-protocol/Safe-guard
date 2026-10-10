// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @dev A venue with the shapes the rule language is weakest on: a `bytesN` head word, a `string` payload, a
///      selector of four zero bytes (`blockHashAskewLimitary(uint256)` hashes to `0x00000000`; the fallback answers it).
contract G12fVenue {
    event Hit(bytes4 selector, bytes data);

    function f(bytes4 x_) external {
        emit Hit(msg.sig, abi.encode(x_));
    }

    function s(string calldata text_) external {
        emit Hit(msg.sig, bytes(text_));
    }

    function w(uint256 x_) external {
        emit Hit(msg.sig, abi.encode(x_));
    }

    fallback() external payable {
        emit Hit(msg.sig, msg.data);
    }

    receive() external payable {}
}

/// @title Round 12 (g12f): boundaries of the rule language, pinned on the real fixture.
/// @notice What the differential fuzz (review-scratch/g12f/fuzz) found at the edges of what a policy can express:
///         the word a `bytesN` parameter occupies is LEFT-aligned (the lint's value grammar right-aligns numbers),
///         a selector of four zero bytes is an ordinary selector, the Safe{Wallet} rejection call is admitted inside
///         a batch and lands in the Safe's `receive()`, a `string` tail is bytes to the guard (the lint's canonical
///         check needs UTF-8), two ceilings on one word are both kept, and an EIP-7702 designator passes the code
///         check as a target and compares as a plain word in a rule.
contract G12fRuleLanguageTest is CuratorGuardTestBase {
    G12fVenue internal venue;
    uint16 internal constant TAIL = 0x8000;

    event Hit(bytes4 selector, bytes data);
    event SafeReceived(address indexed sender, uint256 value);

    function setUp() public override {
        super.setUp();
        venue = new G12fVenue();
        _enforce();
        _registerUnwrapper(address(multiSendCallOnly));
    }

    /*//////////////////////////////////////////////////////////////
                 1. bytesN words are left-aligned in the head
    //////////////////////////////////////////////////////////////*/

    /// @dev The lint accepts `EqualTo "305419896"` (0x12345678 as a number) on a `bytes4` word and writes the
    ///      right-aligned word; the ABI puts `bytes4(0x12345678)` in the HIGH bytes, so no canonical call ever
    ///      matches (a dead function), while the left-aligned word matches exactly (review G12f-1).
    function test_G12f1_right_aligned_value_on_a_bytes4_word_never_matches_the_canonical_call() public {
        bytes memory _call = abi.encodeCall(G12fVenue.f, (bytes4(0x12345678)));
        bytes32 _rightAligned = bytes32(uint256(0x12345678)); // what `toWord("305419896")` yields
        bytes32 _leftAligned = bytes32(bytes4(0x12345678)); // what the calldata word holds
        assertEq(bytes32(this.wordAt(_call, 0)), _leftAligned, "ABI: bytes4 is left-aligned");

        _allowWithRules(address(venue), G12fVenue.f.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _rightAligned));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G12fVenue.f.selector, uint16(0), _leftAligned)
        );
        _execSafeTx(address(venue), 0, _call, Operation.Call);
        // the dry run agrees, and no bytes4 value at all satisfies the right-aligned rule (only the zero word would)
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G12fVenue.f.selector, uint16(0), _leftAligned)
        );
        guard.validateTransaction(address(safe), address(venue), 0, _call, Operation.Call);

        _allowWithRules(address(venue), G12fVenue.f.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _leftAligned));
        vm.expectEmit(true, true, true, true, address(venue));
        emit Hit(G12fVenue.f.selector, abi.encode(bytes4(0x12345678)));
        assertTrue(_execSafeTx(address(venue), 0, _call, Operation.Call));
    }

    /// @dev A ceiling on a `bytesN` word compares the left-aligned word: `LessThanOrEqual(0xffffffff)` (a "bytes4 cap"
    ///      written as a number) admits only `bytes4(0)`, and refuses `bytes4(0x00000001)`.
    function test_G12f1_bound_on_a_bytes4_word_bounds_the_high_bytes() public {
        _allowWithRules(
            address(venue),
            G12fVenue.f.selector,
            _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(0xffffffff)))
        );
        bytes memory _one = abi.encodeCall(G12fVenue.f, (bytes4(0x00000001)));
        vm.expectRevert(
            abi.encodeWithSelector(
                CuratorGuard.ParamRuleViolated.selector, address(venue), G12fVenue.f.selector, uint16(0), bytes32(bytes4(0x00000001))
            )
        );
        guard.validateTransaction(address(safe), address(venue), 0, _one, Operation.Call);
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeCall(G12fVenue.f, (bytes4(0))), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                 2. a selector of four zero bytes
    //////////////////////////////////////////////////////////////*/

    /// @dev `blockHashAskewLimitary(uint256)` has selector `0x00000000`. Allowlisted, it is an ordinary selector:
    ///      four zero bytes plus the word pass the rule, 1-3 zero bytes are `MalformedCalldata`, the bare selector
    ///      is `ParamOutOfRange`, and the empty call stays on the native lane.
    function test_G12f_zero_selector_is_an_ordinary_selector() public {
        assertEq(bytes4(keccak256("blockHashAskewLimitary(uint256)")), bytes4(0), "selector 0");
        _allowWithRules(address(venue), bytes4(0), _rule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(10))));
        bytes memory _ok = abi.encodeWithSelector(bytes4(0), uint256(7));
        vm.expectEmit(true, true, true, true, address(venue));
        emit Hit(bytes4(0), _ok);
        assertTrue(_execSafeTx(address(venue), 0, _ok, Operation.Call));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), bytes4(0), uint16(0), bytes32(uint256(11)))
        );
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeWithSelector(bytes4(0), uint256(11)), Operation.Call);
        vm.expectRevert(CuratorGuard.MalformedCalldata.selector);
        guard.validateTransaction(address(safe), address(venue), 0, hex"000000", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(venue), bytes4(0), uint16(0)));
        guard.validateTransaction(address(safe), address(venue), 0, hex"00000000", Operation.Call);
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.NativeTransferNotAllowed.selector, address(venue)));
        guard.validateTransaction(address(safe), address(venue), 0, "", Operation.Call);
        // inside a batch the entry is held to the same rule
        bytes memory _batch = _multiSendCalldata(abi.encodePacked(_entry(address(venue), 0, _ok), _entry(address(venue), 0, abi.encodeWithSelector(bytes4(0), uint256(11)))));
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), bytes4(0), uint16(0), bytes32(uint256(11)))
        );
        guard.validateTransaction(address(safe), address(multiSendCallOnly), 0, _batch, Operation.DelegateCall);
    }

    /*//////////////////////////////////////////////////////////////
          3. the Safe{Wallet} rejection call inside a batch
    //////////////////////////////////////////////////////////////*/

    /// @dev The one self-call the policy admits is admitted as a batch entry too: the library calls the Safe from
    ///      the Safe's own context, so it lands in `receive()` (`SafeReceived(safe, 0)`), touches nothing and the
    ///      other entries run. With a value or a single byte the entry is `SelfCallNotAllowed(0x00000000)`.
    function test_G12f_rejection_self_call_inside_a_batch_lands_in_receive() public {
        _allow(address(venue), G12fVenue.w.selector);
        bytes memory _w = abi.encodeCall(G12fVenue.w, (5));
        bytes memory _batch = _multiSendCalldata(abi.encodePacked(_entry(address(venue), 0, _w), _entry(address(safe), 0, ""), _entry(address(venue), 0, _w)));
        vm.expectEmit(true, true, true, true, address(safe));
        emit SafeReceived(address(safe), 0);
        assertTrue(_execSafeTx(address(multiSendCallOnly), 0, _batch, Operation.DelegateCall));

        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
        guard.validateTransaction(
            address(safe),
            address(multiSendCallOnly),
            0,
            _multiSendCalldata(abi.encodePacked(_entry(address(venue), 0, _w), _entry(address(safe), 1, ""))),
            Operation.DelegateCall
        );
        vm.expectRevert(abi.encodeWithSelector(CuratorGuard.SelfCallNotAllowed.selector, bytes4(0)));
        guard.validateTransaction(
            address(safe),
            address(multiSendCallOnly),
            0,
            _multiSendCalldata(abi.encodePacked(_entry(address(safe), 0, hex"00"))),
            Operation.DelegateCall
        );
    }

    /*//////////////////////////////////////////////////////////////
                 4. a string tail is bytes to the guard
    //////////////////////////////////////////////////////////////*/

    /// @dev A canonical `s(string)` payload whose bytes are not valid UTF-8 (`0xff`) is bound by its tail hash and
    ///      executes; the lint's canonical check decodes strings as UTF-8 and refuses the raw form of this payload
    ///      ("tail bytes do not decode"), although the venue reads it as bytes (review G12f-2: give the hash).
    function test_G12f2_non_utf8_string_tail_is_bound_and_executes_on_chain() public {
        bytes memory _tail = abi.encode(uint256(0x20), uint256(1), bytes32(hex"ff"));
        bytes memory _call = abi.encodePacked(G12fVenue.s.selector, _tail);
        _allowWithRules(address(venue), G12fVenue.s.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0 | TAIL, keccak256(_tail)));
        vm.expectEmit(true, true, true, true, address(venue));
        emit Hit(G12fVenue.s.selector, hex"ff");
        assertTrue(_execSafeTx(address(venue), 0, _call, Operation.Call));
        // valid UTF-8 ("é") differs in bytes and in hash: refused by the same rule
        bytes memory _other = abi.encodePacked(G12fVenue.s.selector, abi.encode(uint256(0x20), uint256(2), bytes32(hex"c3a9")));
        vm.expectRevert(
            abi.encodeWithSelector(
                CuratorGuard.ParamRuleViolated.selector,
                address(venue),
                G12fVenue.s.selector,
                uint16(0 | TAIL),
                keccak256(abi.encode(uint256(0x20), uint256(2), bytes32(hex"c3a9")))
            )
        );
        guard.validateTransaction(address(safe), address(venue), 0, _other, Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
                 5. two ceilings on one word are both kept
    //////////////////////////////////////////////////////////////*/

    /// @dev The lint refuses two `LessThanOrEqual` rules on one word "(the chain keeps one set / one bound per word)";
    ///      the chain keeps and evaluates both (ANDed, the tighter wins): a precision note on the message.
    function test_G12f_two_ceilings_on_one_word_are_both_evaluated() public {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](2);
        _rules[0] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(9)));
        _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, 0, bytes32(uint256(5)));
        _allowWithRules(address(venue), G12fVenue.w.selector, _rules);
        (, , CuratorGuardPolicy.ParamRule[] memory _stored) = guard.functionPermission(address(safe), address(venue), G12fVenue.w.selector);
        assertEq(_stored.length, 2, "both ceilings stored");
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeCall(G12fVenue.w, (5)), Operation.Call);
        vm.expectRevert(
            abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), G12fVenue.w.selector, uint16(0), bytes32(uint256(7)))
        );
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeCall(G12fVenue.w, (7)), Operation.Call);
    }

    /*//////////////////////////////////////////////////////////////
          6. EIP-7702 designators as a target and as a rule value
    //////////////////////////////////////////////////////////////*/

    /// @dev A designator (`0xef0100 || delegate`, 23 bytes) passes the target code check and the venue's code runs
    ///      in the designator's context; as a rule value it is a plain 20-byte word (`EqualTo` / `OneOf` compare
    ///      words, never code). The sync warns for a designated TARGET only (review g11f); nothing on chain differs.
    function test_G12f_eip7702_designator_as_target_and_as_rule_value() public {
        address _delegated = makeAddr("delegated-eoa");
        vm.etch(_delegated, abi.encodePacked(hex"ef0100", address(venue)));
        assertEq(_delegated.code.length, 23, "designator");
        _allow(_delegated, G12fVenue.w.selector);
        bytes memory _w = abi.encodeCall(G12fVenue.w, (5));
        guard.validateTransaction(address(safe), _delegated, 0, _w, Operation.Call);
        vm.expectEmit(true, true, true, true, _delegated); // the delegate's code runs at the designator's address
        emit Hit(G12fVenue.w.selector, abi.encode(uint256(5)));
        assertTrue(_execSafeTx(_delegated, 0, _w, Operation.Call));
        // as a rule value: word comparison only
        _allowWithRules(address(venue), G12fVenue.w.selector, _rule(CuratorGuardPolicy.RuleKind.EqualTo, 0, _word(_delegated)));
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeCall(G12fVenue.w, (uint256(uint160(_delegated)))), Operation.Call);
        vm.etch(_delegated, ""); // the delegation is cleared: the target fails closed, the rule value still compares
        vm.expectRevert(abi.encodeWithSelector(CuratorGuardPolicy.NotAContract.selector, _delegated));
        guard.validateTransaction(address(safe), _delegated, 0, _w, Operation.Call);
        guard.validateTransaction(address(safe), address(venue), 0, abi.encodeCall(G12fVenue.w, (uint256(uint160(_delegated)))), Operation.Call);
    }

    /// @dev Calldata word `i` of an ABI-encoded call (after the selector).
    function wordAt(bytes calldata data_, uint256 i_) external pure returns (bytes32) {
        return bytes32(data_[4 + 32 * i_:4 + 32 * i_ + 32]);
    }
}
