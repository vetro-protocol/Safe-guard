// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {G10bBase} from "test/guards/G10b_Base.sol";

/// @title Round 10 (g10b): differential corpus against an independent oracle.
/// @dev The oracle `gen.mjs` (node + ethers, written from docs section 4; kept with the round-10 review material) generated the
///      vectors under `test/guards/vectors/`: for each `(to, value, data, operation)` the oracle's verdict is
///      the exact revert data the pre-check must raise (or acceptance) and, for an accepted vector, the hash of
///      the call sequence the Safe must make. This suite replays them against the dry run, the live hooks
///      through the real Safe v1.4.1 fixture, and the three canonical `MultiSendCallOnly` builds (runtime
///      code read from mainnet, hashes equal to the seeded constants).
contract G10bDifferentialTest is G10bBase {
    struct Vec {
        bytes32 callsHash;
        bytes data;
        bytes expect;
        address module;
        uint8 op;
        address to;
        uint256 value;
    }

    function _load(string memory name_) internal view returns (Vec[] memory _v) {
        string memory _json = vm.readFile(string.concat("test/guards/vectors/g10b-", name_, ".json"));
        assertEq(vm.parseJsonBytes32(_json, ".fixtureHash"), _fixtureHash(), "fixture moved: regenerate the vectors");
        bytes[] memory _blobs = abi.decode(vm.parseJson(_json, ".vectors"), (bytes[]));
        _v = new Vec[](_blobs.length);
        for (uint256 i; i < _blobs.length; ++i) {
            // the oracle encodes the seven fields as a flat tuple (no outer offset word)
            (bytes32 _h, bytes memory _d, bytes memory _e, address _m, uint8 _op, address _to, uint256 _val) =
                abi.decode(_blobs[i], (bytes32, bytes, bytes, address, uint8, address, uint256));
            _v[i] = Vec(_h, _d, _e, _m, _op, _to, _val);
        }
    }

    function _dry(Vec memory v_) internal view returns (bytes memory) {
        try guard.validateTransaction(address(safe), v_.to, v_.value, v_.data, Operation(v_.op)) {
            return "";
        } catch (bytes memory _err) {
            return _err;
        }
    }

    function _dryModule(Vec memory v_) internal view returns (bytes memory) {
        try guard.validateModuleTransaction(address(safe), v_.module, v_.to, v_.value, v_.data, Operation(v_.op)) {
            return "";
        } catch (bytes memory _err) {
            return _err;
        }
    }

    function _label(string memory what_, uint256 i_) internal pure returns (string memory) {
        return string.concat(what_, " vector ", vm.toString(i_));
    }

    /*//////////////////////////////////////////////////////////////
                            POLICY PATH
    //////////////////////////////////////////////////////////////*/

    /// @dev Every vector: the dry run's revert data equals the oracle's, byte for byte (selector and arguments).
    function test_policy_dry_run_matches_the_oracle() public view {
        Vec[] memory _v = _load("policy");
        uint256 _accepted;
        for (uint256 i; i < _v.length; ++i) {
            assertEq(_dry(_v[i]), _v[i].expect, _label("policy", i));
            if (_v[i].expect.length == 0) ++_accepted;
        }
        console2.log("policy vectors", _v.length, "accepted", _accepted);
        assertGt(_accepted, _v.length / 16, "corpus too thin");
    }

    /// @dev Every accepted vector executes through the real Safe and the live hooks, and the Safe makes exactly
    ///      the calls the oracle decoded (order, target, value and bytes), nothing else.
    function test_policy_live_hook_executes_exactly_the_oracles_calls() public {
        Vec[] memory _v = _load("policy");
        uint256 _run;
        for (uint256 i; i < _v.length; ++i) {
            if (_v[i].expect.length != 0) continue;
            book.reset();
            assertTrue(_execSafeTx(_v[i].to, _v[i].value, _v[i].data, Operation(_v[i].op)), _label("live", i));
            assertEq(book.digest(), _v[i].callsHash, _label("calls", i));
            ++_run;
        }
        console2.log("live executions", _run);
    }

    /// @dev Every accepted batch runs identically through the canonical v1.3.0, v1.4.1 and v1.5.0 builds
    ///      (the guard-accepted encoding has one meaning for all three), and every refused one is refused
    ///      whichever registered build it addresses.
    function test_accepted_batches_execute_identically_through_the_three_canonical_builds() public {
        Vec[] memory _v = _load("policy");
        address[3] memory _builds = [CAN130, CAN141, CAN150];
        uint256 _run;
        for (uint256 i; i < _v.length; ++i) {
            if (_v[i].op != uint8(Operation.DelegateCall)) continue;
            bool _registered = _v[i].to == address(multiSendCallOnly) || _v[i].to == CAN130 || _v[i].to == CAN141 || _v[i].to == CAN150;
            if (!_registered) continue;
            address _orig = _v[i].to;
            for (uint256 b; b < 3; ++b) {
                Vec memory _w = _v[i]; // a memory alias: `_w.to` is `_v[i].to`, hence `_orig`
                _w.to = _builds[b];
                bytes memory _expect = _v[i].expect;
                // the one refusal that names the unwrapper follows the swap
                if (keccak256(_expect) == keccak256(abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, _orig, bytes4(0x8d80ff0a)))) {
                    _expect = abi.encodeWithSelector(CuratorGuard.ValueNotAllowed.selector, _builds[b], bytes4(0x8d80ff0a));
                }
                assertEq(_dry(_w), _expect, _label("build dry run", i));
                if (_v[i].expect.length != 0) continue;
                book.reset();
                assertTrue(_execSafeTx(_builds[b], 0, _v[i].data, Operation.DelegateCall), _label("build live", i));
                assertEq(book.digest(), _v[i].callsHash, _label("build calls", i));
            }
            if (_v[i].expect.length == 0) ++_run;
        }
        console2.log("batches executed through each canonical build", _run);
        assertGt(_run, 20, "corpus too thin");
    }

    /*//////////////////////////////////////////////////////////////
                           COUNCIL WINDOW
    //////////////////////////////////////////////////////////////*/

    /// @dev Inside a council window the owner-signed path is held to the council's calldata parser only:
    ///      self-calls from the allowlist (thresholds and new-owner words at their documented offsets, exact
    ///      36-byte `setFallbackHandler(0)`, `disableModule` by selector), never the guard, never the policy's
    ///      named handler, delegatecalls only to a registered unwrapper with entries under the same limits.
    function test_council_window_dry_run_matches_the_oracle() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 days);
        Vec[] memory _v = _load("council");
        uint256 _accepted;
        for (uint256 i; i < _v.length; ++i) {
            assertEq(_dry(_v[i]), _v[i].expect, _label("council", i));
            if (_v[i].expect.length == 0) ++_accepted;
        }
        console2.log("council vectors", _v.length, "accepted", _accepted);
        assertGt(_accepted, _v.length / 10, "corpus too thin");
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN WINDOW
    //////////////////////////////////////////////////////////////*/

    /// @dev Inside an admin window nothing is decoded: every vector but a call or delegatecall addressed to the
    ///      guard is accepted, malformed batches and 1-to-3-byte payloads included (section 4, step 5).
    function test_admin_window_dry_run_matches_the_oracle() public {
        _bypass(1 days);
        Vec[] memory _v = _load("adminwindow");
        uint256 _accepted;
        for (uint256 i; i < _v.length; ++i) {
            assertEq(_dry(_v[i]), _v[i].expect, _label("admin window", i));
            if (_v[i].expect.length == 0) ++_accepted;
        }
        console2.log("admin window vectors", _v.length, "accepted", _accepted);
        assertGt(_accepted, _v.length / 2, "corpus too thin");
    }

    /*//////////////////////////////////////////////////////////////
                            MODULE PATH
    //////////////////////////////////////////////////////////////*/

    /// @dev The module path (dry run; the fixture Safe is v1.4.1): the module allowlist first, then the policy
    ///      exactly as on the owner path.
    function test_module_path_dry_run_matches_the_oracle() public view {
        Vec[] memory _v = _load("module");
        uint256 _accepted;
        for (uint256 i; i < _v.length; ++i) {
            assertEq(_dryModule(_v[i]), _v[i].expect, _label("module", i));
            if (_v[i].expect.length == 0) ++_accepted;
        }
        console2.log("module vectors", _v.length, "accepted", _accepted);
        assertGt(_accepted, _v.length / 20, "corpus too thin");
    }
}
