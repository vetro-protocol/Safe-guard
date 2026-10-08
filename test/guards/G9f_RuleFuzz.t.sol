// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";
import {G9fSink} from "test/guards/G9fBase.sol";

/// @title Round 9 (g9f): the rule evaluation and the rule-shape validation, fuzzed against a
///        reference written from docs/curator-guard.md section 4 ("Rule kinds") and section 5.
/// @dev The repository fuzzes `LessThanOrEqual` only; every kind, the tail flag, missing words,
///      dirty words and the ANDed order are example-based. Here one random rule list (one kind, or the
///      floor + ceiling pair) is applied to a venue, a random calldata is evaluated by the reference,
///      by the dry run and by the live hook through the real Safe, and the three must agree byte for
///      byte on the verdict (pass, `ParamOutOfRange(wordIndex)` or `ParamRuleViolated(wordIndex, word)`).
contract CuratorGuardG9fRuleFuzzTest is CuratorGuardTestBase {
    bytes4 internal constant SEL = 0xabcdef01;
    uint16 internal constant TAIL = 0x8000;
    G9fSink internal venue;

    function setUp() public override {
        super.setUp();
        venue = new G9fSink();
        _enforce();
    }

    /*//////////////////////////////////////////////////////////////
                                REFERENCE
    //////////////////////////////////////////////////////////////*/

    /// @dev Section 4: the subject is the word at `4 + 32 * (wordIndex & 0x7fff)`, or with the tail
    ///      flag the hash of the calldata from that word on; a missing word is out of range; rules are
    ///      ANDed in order and the first failing one names the verdict.
    function _reference(
        CuratorGuardPolicy.ParamRule[] memory rules_,
        bytes32[] memory members_,
        bytes memory data_
    ) internal view returns (bytes memory) {
        for (uint256 i; i < rules_.length; ++i) {
            CuratorGuardPolicy.ParamRule memory _r = rules_[i];
            uint256 _start = 4 + 32 * uint256(_r.wordIndex & ~TAIL);
            if (data_.length < _start + 32) {
                return abi.encodeWithSelector(CuratorGuard.ParamOutOfRange.selector, address(venue), SEL, _r.wordIndex);
            }
            bytes32 _word = _r.wordIndex & TAIL != 0 ? keccak256(_slice(data_, _start, data_.length)) : bytes32(_slice(data_, _start, _start + 32));
            bool _ok;
            if (_r.kind == CuratorGuardPolicy.RuleKind.EqualTo) _ok = _word == _r.value;
            else if (_r.kind == CuratorGuardPolicy.RuleKind.EqualToSafe) _ok = _word == bytes32(uint256(uint160(address(safe))));
            else if (_r.kind == CuratorGuardPolicy.RuleKind.OneOf) _ok = _isMember(members_, _word);
            else if (_r.kind == CuratorGuardPolicy.RuleKind.LessThanOrEqual) _ok = uint256(_word) <= uint256(_r.value);
            else _ok = uint256(_word) >= uint256(_r.value);
            if (!_ok) {
                return abi.encodeWithSelector(CuratorGuard.ParamRuleViolated.selector, address(venue), SEL, _r.wordIndex, _word);
            }
        }
        return "";
    }

    function _isMember(bytes32[] memory set_, bytes32 w_) internal pure returns (bool) {
        for (uint256 i; i < set_.length; ++i) if (set_[i] == w_) return true;
        return false;
    }

    function _slice(bytes memory b_, uint256 from_, uint256 to_) internal pure returns (bytes memory _out) {
        _out = new bytes(to_ - from_);
        for (uint256 i; i < _out.length; ++i) _out[i] = b_[from_ + i];
    }

    /*//////////////////////////////////////////////////////////////
                              RULE EVALUATION
    //////////////////////////////////////////////////////////////*/

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_rule_evaluation_matches_the_reference_on_dry_run_and_live_hook(
        uint8 kindRaw_,
        uint8 wordRaw_,
        bool tail_,
        bool plant_,
        bytes32 value_,
        bytes32 ceilingRaw_,
        uint8 membersRaw_,
        bytes calldata payload_
    ) public {
        CuratorGuardPolicy.RuleKind _kind = CuratorGuardPolicy.RuleKind(kindRaw_ % 5);
        uint16 _wordIndex = uint16(wordRaw_ % 12) | (tail_ ? TAIL : 0);
        uint256 _start = 4 + 32 * uint256(_wordIndex & ~TAIL);
        bytes memory _data = abi.encodePacked(SEL, payload_.length > 420 ? payload_[:420] : payload_);

        // The rule list (one rule, or the paired floor + ceiling), with values the contract accepts.
        CuratorGuardPolicy.ParamRule[] memory _rules;
        bytes32 _ruleValue = value_;
        if (_kind == CuratorGuardPolicy.RuleKind.EqualToSafe || _kind == CuratorGuardPolicy.RuleKind.OneOf) _ruleValue = 0;
        if (_kind == CuratorGuardPolicy.RuleKind.GreaterThanOrEqual) {
            if (_ruleValue == bytes32(type(uint256).max)) _ruleValue = bytes32(type(uint256).max - 1);
            uint256 _ceiling = bound(uint256(ceilingRaw_), uint256(_ruleValue), type(uint256).max - 1);
            _rules = new CuratorGuardPolicy.ParamRule[](2);
            _rules[0] = CuratorGuardPolicy.ParamRule(_kind, _wordIndex, _ruleValue);
            _rules[1] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, _wordIndex, bytes32(_ceiling));
        } else {
            _rules = new CuratorGuardPolicy.ParamRule[](1);
            _rules[0] = CuratorGuardPolicy.ParamRule(_kind, _wordIndex, _ruleValue);
        }
        // Plant a passing subject half of the time so the pass branch is exercised as often as the
        // refusals: the word itself (or, for a tail rule, the rule value) is made to match.
        bytes32[] memory _members = new bytes32[](membersRaw_ % 4);
        for (uint256 i; i < _members.length; ++i) _members[i] = keccak256(abi.encode(value_, i));
        if (plant_ && _data.length >= _start + 32) {
            if (!tail_) {
                bytes32 _w = _kind == CuratorGuardPolicy.RuleKind.EqualToSafe
                    ? bytes32(uint256(uint160(address(safe))))
                    : (_kind == CuratorGuardPolicy.RuleKind.OneOf ? (_members.length > 0 ? _members[0] : value_) : _ruleValue);
                for (uint256 i; i < 32; ++i) _data[_start + i] = _w[i];
            } else {
                bytes32 _h = keccak256(_slice(_data, _start, _data.length));
                if (_kind == CuratorGuardPolicy.RuleKind.EqualTo || _kind == CuratorGuardPolicy.RuleKind.LessThanOrEqual) {
                    _rules[0].value = _h;
                } else if (_kind == CuratorGuardPolicy.RuleKind.OneOf && _members.length > 0) {
                    _members[0] = _h;
                } else if (_kind == CuratorGuardPolicy.RuleKind.GreaterThanOrEqual) {
                    _rules[0].value = _h;
                    _rules[1].value = _h;
                }
            }
        }
        _allowWithRules(address(venue), SEL, _rules);
        if (_kind == CuratorGuardPolicy.RuleKind.OneOf && _members.length > 0) {
            vm.prank(vetro);
            guard.addAllowedValues(address(safe), address(venue), SEL, _wordIndex, _members);
        }

        bytes memory _expected = _reference(_rules, _members, _data);
        bytes memory _got;
        try guard.validateTransaction(address(safe), address(venue), 0, _data, Operation.Call) {} catch (bytes memory _e) {
            _got = _e;
        }
        assertEq(_got, _expected, "dry run == reference");
        if (_expected.length == 0) {
            assertTrue(_execSafeTx(address(venue), 0, _data, Operation.Call), "live hook passes");
            assertEq(venue.calls(), 1);
        } else {
            vm.expectRevert(_expected);
            _execSafeTx(address(venue), 0, _data, Operation.Call);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            RULE-SHAPE VALIDATION
    //////////////////////////////////////////////////////////////*/

    /// @dev Section 5: `EqualToSafe` / `OneOf` carry no value; a floor needs a ceiling on the same word
    ///      (`LessThanOrEqual` not below the floor and not 2^256-1, or `EqualTo` / `OneOf`); the first
    ///      offending rule, in order, names the verdict.
    function _referenceShape(CuratorGuardPolicy.ParamRule[] memory rules_) internal pure returns (bytes memory) {
        if (rules_.length > 16) return abi.encodeWithSelector(CuratorGuardPolicy.TooManyRules.selector, rules_.length);
        for (uint256 i; i < rules_.length; ++i) {
            CuratorGuardPolicy.ParamRule memory _r = rules_[i];
            if ((_r.kind == CuratorGuardPolicy.RuleKind.EqualToSafe || _r.kind == CuratorGuardPolicy.RuleKind.OneOf) && _r.value != 0) {
                return abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, i);
            }
            if (_r.kind != CuratorGuardPolicy.RuleKind.GreaterThanOrEqual) continue;
            bool _bounded;
            for (uint256 j; j < rules_.length; ++j) {
                CuratorGuardPolicy.ParamRule memory _u = rules_[j];
                if (_u.wordIndex != _r.wordIndex) continue;
                if (_u.kind == CuratorGuardPolicy.RuleKind.LessThanOrEqual) {
                    if (uint256(_u.value) < uint256(_r.value) || _u.value == bytes32(type(uint256).max)) {
                        return abi.encodeWithSelector(CuratorGuardPolicy.InvalidRule.selector, i);
                    }
                    _bounded = true;
                } else if (_u.kind == CuratorGuardPolicy.RuleKind.EqualTo || _u.kind == CuratorGuardPolicy.RuleKind.OneOf) {
                    _bounded = true;
                }
            }
            if (!_bounded) return abi.encodeWithSelector(CuratorGuardPolicy.UnboundedLowerBound.selector, i);
        }
        return "";
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_rule_shape_validation_matches_the_reference(
        uint8[6] memory kinds_,
        uint8[6] memory words_,
        bytes32[6] memory values_,
        uint8 nRaw_,
        bool extremes_
    ) public {
        uint256 _n = nRaw_ % 7;
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](_n);
        for (uint256 i; i < _n; ++i) {
            bytes32 _v = values_[i];
            // Steer towards the interesting values: zero, the maximum, and small numbers that collide.
            if (extremes_) _v = uint8(_v[31]) % 4 == 0 ? bytes32(0) : uint8(_v[31]) % 4 == 1 ? bytes32(type(uint256).max) : bytes32(uint256(uint8(_v[30]) % 8));
            _rules[i] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind(kinds_[i] % 5), uint16(words_[i] % 3) | (words_[i] > 200 ? TAIL : 0), _v);
        }
        bytes memory _expected = _referenceShape(_rules);
        bytes memory _got;
        vm.prank(vetro);
        try guard.allowFunction(address(safe), address(venue), SEL, false, _rules) {} catch (bytes memory _e) {
            _got = _e;
        }
        assertEq(_got, _expected, "allowFunction == reference");
        (bool _allowed, , CuratorGuardPolicy.ParamRule[] memory _stored) = guard.functionPermission(address(safe), address(venue), SEL);
        assertEq(_allowed, _expected.length == 0, "stored iff accepted");
        if (_allowed) assertEq(_stored.length, _n, "every rule stored");
    }
}
