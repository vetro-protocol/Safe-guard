// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

/// @title Round 11 (g11d): specification-to-test traceability, mechanically.
/// @notice The ten-rule header of `CuratorGuard.sol` is the specification the suites pin, and nothing
///         tied the two together (reviews g9g, g10g). This suite reads the three contracts, the docs
///         and every suite under `test/guards/` and fails on drift: an error the header names that no
///         contract declares, a declared error no test expects, a declared event no test asserts, and a
///         hook error the signers' table (docs section 7.8) does not list.
/// @dev   Needs `fs_permissions` read access to `contracts/guards`, `docs/curator-guard.md` and
///        `test/guards` under the `guards` profile. Sources are scanned one file at a time with
///        `vm.split`, never concatenated, so the EVM memory limit is never approached.
contract G11dTraceabilityTest is Test {
    string internal constant GUARD = "contracts/guards/CuratorGuard.sol";
    string internal constant POLICY = "contracts/guards/CuratorGuardPolicy.sol";
    string internal constant TIMELOCK = "contracts/guards/CuratorGuardTimelock.sol";
    string internal constant DOCS = "docs/curator-guard.md";
    string internal constant TESTS = "test/guards";
    string internal constant SELF = "G11d_Traceability.t.sol";

    string[] internal errors; // every custom error the three contracts declare
    string[] internal guardErrors; // the ones `CuratorGuard.sol` declares (raised by the hooks)
    string[] internal events; // every event the three contracts declare
    mapping(bytes32 => bool) internal isError;
    mapping(bytes32 => bool) internal isEvent;
    mapping(bytes32 => bool) internal expectedByATest; // `<Name>.selector` appears in a test source
    mapping(bytes32 => bool) internal assertedByATest; // `emit <Name>(` or `keccak256("<Name>(` appears in a test source

    function setUp() public {
        _collect(GUARD, true);
        _collect(POLICY, false);
        _collect(TIMELOCK, false);
        _scanTests();
    }

    /*//////////////////////////////////////////////////////////////
                                 TESTS
    //////////////////////////////////////////////////////////////*/

    /// @dev The test g10g asked for: every error name the ten-rule header cites is a declared error that
    ///      some test expects; every other CamelCase identifier the header cites is an event, or one of
    ///      the few non-error names listed here (a renamed error leaves a stale citation and fails).
    function test_the_ten_rule_header_cites_declared_errors_that_some_test_raises() public view {
        string memory _header = vm.split(vm.readFile(GUARD), "contract CuratorGuard is")[0];
        string[] memory _parts = vm.split(_header, "`");
        uint256 _cited;
        for (uint256 i = 1; i < _parts.length; i += 2) {
            string memory _token = _parts[i];
            if (!_isUpperIdentifier(_token)) continue;
            bytes32 _k = keccak256(bytes(_token));
            if (isError[_k]) {
                assertTrue(expectedByATest[_k], string.concat("header error raised by no test: ", _token));
                ++_cited;
            } else if (!isEvent[_k]) {
                assertTrue(_isHeaderNonErrorName(_token), string.concat("header cites an undeclared name: ", _token));
            }
        }
        // The citations present at review time (rules 1, 2, 4, 6, 8 and the post-execution paragraph);
        // a rewrite that drops one has to update this list on purpose.
        string[9] memory _frozen = [
            "NestedExecution",
            "GuardNotInstalled",
            "GuardCallNotAllowed",
            "ForwardedHookCall",
            "ApprovedExecutionFailed",
            "SafeNotSupported",
            "ModuleNotHooked",
            "MissingSnapshot",
            "SafeConfigUnreadable"
        ];
        for (uint256 i; i < _frozen.length; ++i) {
            assertTrue(_contains(_header, string.concat("`", _frozen[i], "`")), string.concat("header no longer cites ", _frozen[i]));
        }
        assertGe(_cited, _frozen.length, "fewer error citations than frozen");
    }

    /// @dev Every custom error of the three contracts is expected (`<Name>.selector`) by at least one
    ///      suite under `test/guards/`.
    function test_every_declared_error_is_expected_by_some_test() public view {
        for (uint256 i; i < errors.length; ++i) {
            assertTrue(expectedByATest[keccak256(bytes(errors[i]))], string.concat("error expected by no test: ", errors[i]));
        }
        assertEq(errors.length, 57, "error count moved: update the matrix");
    }

    /// @dev Every event of the three contracts is asserted (`emit <Name>(` under `expectEmit`, or its
    ///      topic signature under `recordLogs`) by at least one suite. Docs section 7.7 tells indexers
    ///      to rely on each of them.
    function test_every_declared_event_is_asserted_by_some_test() public view {
        for (uint256 i; i < events.length; ++i) {
            assertTrue(assertedByATest[keccak256(bytes(events[i]))], string.concat("event asserted by no test: ", events[i]));
        }
        assertEq(events.length, 16, "event count moved: update the matrix");
    }

    /// @dev Docs section 7.8 ("What the curator's signers will see") lists every error the hooks can raise
    ///      on a Safe transaction: the errors `CuratorGuard.sol` declares plus the four policy errors the
    ///      hook path raises; and every name it lists is a declared error (or OpenZeppelin's `FailedCall`).
    function test_docs_78_signer_table_lists_every_hook_error() public view {
        string memory _section = vm.split(vm.split(vm.readFile(DOCS), "### 7.8")[1], "## 8.")[0];
        string[] memory _rows = vm.split(_section, "\n");
        string[] memory _listed = new string[](64);
        uint256 _n;
        for (uint256 r; r < _rows.length; ++r) {
            if (!_startsWith(_rows[r], "| `")) continue;
            string[] memory _tokens = vm.split(vm.split(_rows[r], "|")[1], "`");
            for (uint256 i = 1; i < _tokens.length; i += 2) {
                string memory _name = _stripCall(_tokens[i]);
                if (!_isUpperIdentifier(_name)) continue; // prose such as `execute`
                assertTrue(
                    isError[keccak256(bytes(_name))] || _eq(_name, "FailedCall"),
                    string.concat("7.8 names an undeclared error: ", _name)
                );
                _listed[_n++] = _name;
            }
        }
        for (uint256 i; i < guardErrors.length; ++i) {
            assertTrue(_in(_listed, _n, guardErrors[i]), string.concat("7.8 omits the hook error ", guardErrors[i]));
        }
        string[4] memory _policyHookErrors = ["ModuleNotAllowed", "UnwrapperCodehashNotAllowed", "NotAContract", "LockdownCooldown"];
        for (uint256 i; i < _policyHookErrors.length; ++i) {
            assertTrue(_in(_listed, _n, _policyHookErrors[i]), string.concat("7.8 omits ", _policyHookErrors[i]));
        }
    }

    /*//////////////////////////////////////////////////////////////
                               SCANNING
    //////////////////////////////////////////////////////////////*/

    function _collect(string memory path_, bool guard_) internal {
        string[] memory _lines = vm.split(vm.readFile(path_), "\n");
        for (uint256 i; i < _lines.length; ++i) {
            string memory _t = vm.trim(_lines[i]);
            if (_startsWith(_t, "error ")) {
                string memory _name = _leadingIdentifier(_substring(_t, 6), false);
                errors.push(_name);
                if (guard_) guardErrors.push(_name);
                isError[keccak256(bytes(_name))] = true;
            } else if (_startsWith(_t, "event ")) {
                string memory _name = _leadingIdentifier(_substring(_t, 6), false);
                events.push(_name);
                isEvent[keccak256(bytes(_name))] = true;
            }
        }
    }

    function _scanTests() internal {
        Vm.DirEntry[] memory _entries = vm.readDir(TESTS);
        for (uint256 e; e < _entries.length; ++e) {
            string memory _path = _entries[e].path;
            if (_entries[e].isDir || !_endsWith(_path, ".sol") || _contains(_path, SELF)) continue;
            string memory _src = vm.readFile(_path);
            string[] memory _parts = vm.split(_src, ".selector");
            for (uint256 i; i + 1 < _parts.length; ++i) {
                expectedByATest[keccak256(bytes(_trailingIdentifier(_parts[i])))] = true;
            }
            _parts = vm.split(_src, "emit ");
            for (uint256 i = 1; i < _parts.length; ++i) {
                assertedByATest[keccak256(bytes(_leadingIdentifier(_parts[i], true)))] = true;
            }
            _parts = vm.split(_src, "keccak256(\"");
            for (uint256 i = 1; i < _parts.length; ++i) {
                assertedByATest[keccak256(bytes(_leadingIdentifier(_parts[i], false)))] = true;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                             STRING HELPERS
    //////////////////////////////////////////////////////////////*/

    function _isHeaderNonErrorName(string memory t_) internal pure returns (bool) {
        return
            _eq(t_, "MultiSendCallOnly") ||
            _eq(t_, "Bypass") ||
            _eq(t_, "CuratorGuardPolicy") ||
            _eq(t_, "APPROVED_SENTINEL") ||
            _eq(t_, "INVALID");
    }

    function _isIdentChar(bytes1 c_) internal pure returns (bool) {
        return (c_ >= "a" && c_ <= "z") || (c_ >= "A" && c_ <= "Z") || (c_ >= "0" && c_ <= "9") || c_ == "_";
    }

    /// @dev `[A-Z][A-Za-z0-9_]*`, nothing else (no dots, parentheses or spaces).
    function _isUpperIdentifier(string memory s_) internal pure returns (bool) {
        bytes memory _b = bytes(s_);
        if (_b.length == 0 || !(_b[0] >= "A" && _b[0] <= "Z")) return false;
        for (uint256 i; i < _b.length; ++i) if (!_isIdentChar(_b[i])) return false;
        return true;
    }

    /// @dev The identifier a string starts with; with `dots_`, a `Contract.` prefix is skipped.
    function _leadingIdentifier(string memory s_, bool dots_) internal pure returns (string memory) {
        bytes memory _b = bytes(s_);
        uint256 _end;
        uint256 _start;
        while (_end < _b.length && (_isIdentChar(_b[_end]) || (dots_ && _b[_end] == "."))) {
            if (_b[_end] == ".") _start = _end + 1;
            ++_end;
        }
        return _slice(_b, _start, _end);
    }

    /// @dev The identifier a string ends with (`CuratorGuard.SafeLockedDown` gives `SafeLockedDown`).
    function _trailingIdentifier(string memory s_) internal pure returns (string memory) {
        bytes memory _b = bytes(s_);
        uint256 _start = _b.length;
        while (_start > 0 && _isIdentChar(_b[_start - 1])) --_start;
        return _slice(_b, _start, _b.length);
    }

    /// @dev `FailedCall()` gives `FailedCall`.
    function _stripCall(string memory s_) internal pure returns (string memory) {
        bytes memory _b = bytes(s_);
        uint256 _end;
        while (_end < _b.length && _isIdentChar(_b[_end])) ++_end;
        return _slice(_b, 0, _end);
    }

    function _slice(bytes memory b_, uint256 start_, uint256 end_) internal pure returns (string memory) {
        bytes memory _out = new bytes(end_ - start_);
        for (uint256 i = start_; i < end_; ++i) _out[i - start_] = b_[i];
        return string(_out);
    }

    function _substring(string memory s_, uint256 from_) internal pure returns (string memory) {
        return _slice(bytes(s_), from_, bytes(s_).length);
    }

    function _startsWith(string memory s_, string memory p_) internal pure returns (bool) {
        bytes memory _s = bytes(s_);
        bytes memory _p = bytes(p_);
        if (_p.length > _s.length) return false;
        for (uint256 i; i < _p.length; ++i) if (_s[i] != _p[i]) return false;
        return true;
    }

    function _endsWith(string memory s_, string memory p_) internal pure returns (bool) {
        bytes memory _s = bytes(s_);
        bytes memory _p = bytes(p_);
        if (_p.length > _s.length) return false;
        uint256 _off = _s.length - _p.length;
        for (uint256 i; i < _p.length; ++i) if (_s[_off + i] != _p[i]) return false;
        return true;
    }

    function _contains(string memory s_, string memory key_) internal pure returns (bool) {
        return vm.indexOf(s_, key_) != type(uint256).max;
    }

    function _eq(string memory a_, string memory b_) internal pure returns (bool) {
        return keccak256(bytes(a_)) == keccak256(bytes(b_));
    }

    function _in(string[] memory list_, uint256 n_, string memory name_) internal pure returns (bool) {
        for (uint256 i; i < n_; ++i) if (_eq(list_[i], name_)) return true;
        return false;
    }
}
