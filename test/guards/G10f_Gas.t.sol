// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CuratorGuard} from "contracts/guards/CuratorGuard.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {Operation} from "contracts/interfaces/safe/ISafeGuard.sol";
import {CuratorGuardTestBase} from "test/guards/CuratorGuardTestBase.sol";

/// @dev Accepts any call: stands in, at their mainnet addresses, for the five vaults and the five tokens of
///      the shipped policy (the hooks only need code at a target; nothing here calls them).
contract G10fSink {
    uint256 public calls;

    fallback() external payable {
        ++calls;
    }

    receive() external payable {
        ++calls;
    }
}

/// @title Round 10 (g10f): gas of every hook path on the SHIPPED policy shape, and the worst case of each.
/// @dev   The policy file is applied to the local Safe v1.4.1 fixture (four owners like the live Safe, the
///        three canonical unwrapper addresses carrying the locally compiled `MultiSendCallOnly`, sink code
///        at every policy target). Direct hook calls as the Safe (gasleft deltas, call overhead included),
///        cold first, then warm. The worst cases scale the inputs the guard's cost depends on: rules per
///        function (`MAX_RULES`), the length of a tail-hashed payload, entries per batch, owners per Safe,
///        self-calls per council-window batch, entries per approved batch. Numbers are logged; the
///        assertions are ceilings and slopes, loose enough to survive an optimizer change and tight enough
///        to catch a path going quadratic. Fork counterpart on the live Safe: `G9f_Gas.e2e.ethereum.t.sol`.
abstract contract G10fGasBase is CuratorGuardTestBase {
    address internal constant MULTISEND_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant VAULT_USDC = 0x131CcfDFfeD712885aAc31445d351E6b62656679;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes4 internal constant SEL_NAV = bytes4(keccak256("updateNewTotalAssets(uint256)"));
    bytes4 internal constant SEL_SETTLE = bytes4(keccak256("settleDeposit(uint256)"));
    bytes4 internal constant SEL_APPROVE = bytes4(keccak256("approve(address,uint256)"));

    bytes internal sinkCode;
    bytes internal navData;
    bytes internal approveData;
    bytes internal batchData;

    function setUp() public virtual override {
        super.setUp();
        sinkCode = address(new G10fSink()).code;
        for (uint256 i; i < 3; ++i) _addOwner(makeAddr(string.concat("owner-", vm.toString(i))));
        _applyShippedPolicy("policies/curator-guard/vetro-lagoon.ethereum.json");
        navData = abi.encodeWithSelector(SEL_NAV, uint256(1_000_000e6));
        approveData = abi.encodeWithSelector(SEL_APPROVE, VAULT_USDC, type(uint256).max);
        batchData = _multiSendCalldata(
            abi.encodePacked(_entry(VAULT_USDC, 0, navData), _entry(VAULT_USDC, 0, abi.encodeWithSelector(SEL_SETTLE, uint256(1_000_000e6))))
        );
    }

    /*//////////////////////////////////////////////////////////////
                                 HELPERS
    //////////////////////////////////////////////////////////////*/

    function _addOwner(address owner_) internal {
        vm.prank(address(safe));
        safe.addOwnerWithThreshold(owner_, 1);
    }

    /// @dev The repository policy file, as `curator-guard-sync` would apply it (unwrappers, functions with
    ///      their `OneOf` sets, guardians, the handler requirement, the mode).
    function _applyShippedPolicy(string memory path_) internal {
        string memory _json = vm.readFile(path_);
        _seedCodehash(address(multiSendCallOnly).codehash);
        vm.startPrank(vetro);
        address[] memory _unwrappers = vm.parseJsonAddressArray(_json, ".multiSendUnwrappers");
        for (uint256 i; i < _unwrappers.length; ++i) {
            vm.etch(_unwrappers[i], address(multiSendCallOnly).code);
            guard.setMultiSendUnwrapper(address(safe), _unwrappers[i], true);
        }
        for (uint256 i; ; ++i) {
            string memory _base = string.concat(".functions[", vm.toString(i), "]");
            if (!vm.keyExistsJson(_json, string.concat(_base, ".target"))) break;
            address _target = vm.parseJsonAddress(_json, string.concat(_base, ".target"));
            if (_target.code.length == 0) vm.etch(_target, sinkCode);
            bytes4 _selector = bytes4(keccak256(bytes(vm.parseJsonString(_json, string.concat(_base, ".signature")))));
            uint256 _ruleCount;
            while (vm.keyExistsJson(_json, string.concat(_base, ".rules[", vm.toString(_ruleCount), "]"))) ++_ruleCount;
            CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](_ruleCount);
            for (uint256 j; j < _ruleCount; ++j) {
                string memory _r = string.concat(_base, ".rules[", vm.toString(j), "]");
                assertEq(vm.parseJsonString(_json, string.concat(_r, ".kind")), "OneOf", "fixture supports OneOf rules");
                _rules[j] = CuratorGuardPolicy.ParamRule(
                    CuratorGuardPolicy.RuleKind.OneOf,
                    uint16(vm.parseJsonUint(_json, string.concat(_r, ".wordIndex"))),
                    0
                );
            }
            guard.allowFunction(address(safe), _target, _selector, false, _rules);
            for (uint256 j; j < _ruleCount; ++j) {
                string memory _r = string.concat(_base, ".rules[", vm.toString(j), "]");
                address[] memory _values = vm.parseJsonAddressArray(_json, string.concat(_r, ".values"));
                bytes32[] memory _words = new bytes32[](_values.length);
                for (uint256 k; k < _values.length; ++k) _words[k] = _word(_values[k]);
                guard.addAllowedValues(address(safe), _target, _selector, _rules[j].wordIndex, _words);
            }
        }
        address[] memory _guardians = vm.parseJsonAddressArray(_json, ".guardians");
        for (uint256 i; i < _guardians.length; ++i) guard.setGuardian(address(safe), _guardians[i], true);
        guard.setRequiredFallbackHandler(
            address(safe),
            vm.parseJsonAddress(_json, ".requiredFallbackHandler.handler"),
            vm.parseJsonBool(_json, ".requiredFallbackHandler.enforce")
        );
        guard.enforce(address(safe));
        vm.stopPrank();
        assertEq(guard.targets(address(safe)).length, 10, "five vaults and five tokens");
    }

    function _pre(address to_, uint256 value_, bytes memory data_, Operation op_) internal returns (uint256 _gas) {
        vm.prank(address(safe));
        _gas = gasleft();
        guard.checkTransaction(to_, value_, data_, op_, 0, 0, 0, address(0), payable(address(0)), "", curator);
        _gas -= gasleft();
    }

    function _post() internal returns (uint256 _gas) {
        vm.prank(address(safe));
        _gas = gasleft();
        guard.checkAfterExecution(bytes32(uint256(1)), true);
        _gas -= gasleft();
    }

    function _dry(address to_, bytes memory data_, Operation op_) internal view returns (uint256 _gas) {
        _gas = gasleft();
        guard.validateTransaction(address(safe), to_, 0, data_, op_);
        _gas -= gasleft();
    }

    function _log(string memory what_, uint256 gas_) internal {
        emit log_named_uint(what_, gas_);
    }

}

/// @dev The shipped policy and the worst cases that need no cold state.
contract CuratorGuardG10fGasTest is G10fGasBase {
    /*//////////////////////////////////////////////////////////////
                           THE SHIPPED POLICY
    //////////////////////////////////////////////////////////////*/

    /// @dev Every path of both hooks on the shipped policy: policy (plain call without rules, with the
    ///      `OneOf` rule, the settlement batch), the dry run, the approval path, the council window (plain
    ///      and batch), the admin window, and the module path (the module-guard slot planted on the
    ///      v1.4.1 fixture, which has no `setModuleGuard`).
    function test_shipped_policy_every_hook_path() public {
        uint256 _preCold = _pre(VAULT_USDC, 0, navData, Operation.Call);
        uint256 _postCold = _post();
        uint256 _preWarm = _pre(VAULT_USDC, 0, navData, Operation.Call);
        uint256 _postWarm = _post();
        _log("policy: pre-hook updateNewTotalAssets (no rules), cold", _preCold);
        _log("policy: pre-hook updateNewTotalAssets (no rules), warm", _preWarm);
        _log("policy: after-hook (4 owners), cold", _postCold);
        _log("policy: after-hook (4 owners), warm", _postWarm);
        assertLt(_preCold, 100_000, "pre-hook cold ceiling");
        assertLt(_postCold, 40_000, "after-hook ceiling");

        _preCold = _pre(USDC, 0, approveData, Operation.Call);
        _post();
        _preWarm = _pre(USDC, 0, approveData, Operation.Call);
        _post();
        _log("policy: pre-hook approve(vault, max) with OneOf, cold", _preCold);
        _log("policy: pre-hook approve(vault, max) with OneOf, warm", _preWarm);

        _preCold = _pre(MULTISEND_141, 0, batchData, Operation.DelegateCall);
        _post();
        _preWarm = _pre(MULTISEND_141, 0, batchData, Operation.DelegateCall);
        _post();
        _log("policy: pre-hook settlement batch (2 entries), cold", _preCold);
        _log("policy: pre-hook settlement batch (2 entries), warm", _preWarm);

        _log("dry run: validateTransaction updateNewTotalAssets, warm", _dry(VAULT_USDC, navData, Operation.Call));
        _log("dry run: validateTransaction settlement batch, warm", _dry(MULTISEND_141, batchData, Operation.DelegateCall));

        vm.prank(council);
        guard.approveTransaction(address(safe), address(0), VAULT_USDC, 0, navData, Operation.Call, 1 days);
        uint256 _g = _pre(VAULT_USDC, 0, navData, Operation.Call);
        uint256 _p = _post();
        _log("approval: pre-hook (consumes), warm", _g);
        _log("approval: after-hook (sentinel)", _p);

        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        _g = _pre(VAULT_USDC, 0, navData, Operation.Call);
        _p = _post();
        _log("council window: pre-hook plain call", _g);
        _log("council window: after-hook", _p);
        _g = _pre(MULTISEND_141, 0, batchData, Operation.DelegateCall);
        _post();
        _log("council window: pre-hook batch (2 entries)", _g);
        vm.prank(vetro);
        guard.enforce(address(safe));

        vm.prank(vetro);
        guard.bypass(address(safe), 1 hours);
        _g = _pre(VAULT_USDC, 0, navData, Operation.Call);
        _p = _post();
        _log("admin window: pre-hook plain call", _g);
        _log("admin window: after-hook", _p);
        vm.prank(vetro);
        guard.enforce(address(safe));

        address _module = makeAddr("module");
        vm.store(address(safe), MODULE_GUARD_SLOT, bytes32(uint256(uint160(address(guard)))));
        vm.prank(vetro);
        guard.setModuleAllowed(address(safe), _module, true);
        vm.prank(address(safe));
        _g = gasleft();
        bytes32 _hash = guard.checkModuleTransaction(VAULT_USDC, 0, navData, Operation.Call, _module);
        _g -= gasleft();
        vm.prank(address(safe));
        _p = gasleft();
        guard.checkAfterModuleExecution(_hash, true);
        _p -= gasleft();
        _log("module path (policy): pre-hook updateNewTotalAssets", _g);
        _log("module path (policy): after-hook", _p);

        vm.prank(vetro);
        _g = gasleft();
        guard.checkTransaction(VAULT_USDC, 0, navData, Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", vetro);
        _g -= gasleft();
        _log("the admin's own transaction: pre-hook (exempt)", _g);
    }

    /*//////////////////////////////////////////////////////////////
                              WORST CASES
    //////////////////////////////////////////////////////////////*/

    /// @dev `MAX_RULES` (16) on one function, every kind, four full `OneOf` sets (128 members: `contains`
    ///      is one keccak and one SLOAD whatever the size).
    function test_worst_case_sixteen_rules_of_every_kind() public {
        CuratorGuardPolicy.ParamRule[] memory _rules = new CuratorGuardPolicy.ParamRule[](16);
        bytes memory _data = abi.encodePacked(SEL_SETTLE);
        for (uint16 w; w < 4; ++w) {
            _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualTo, w, bytes32(uint256(w + 1)));
            _data = abi.encodePacked(_data, uint256(w + 1));
        }
        for (uint16 w = 4; w < 8; ++w) {
            _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.EqualToSafe, w, 0);
            _data = abi.encodePacked(_data, _word(address(safe)));
        }
        for (uint16 w = 8; w < 12; ++w) {
            _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.OneOf, w, 0);
            _data = abi.encodePacked(_data, bytes32(uint256(0x1000 + 127))); // the last member added
        }
        for (uint16 w = 12; w < 14; ++w) {
            _rules[w] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.GreaterThanOrEqual, w, bytes32(uint256(1)));
            _rules[w + 2] = CuratorGuardPolicy.ParamRule(CuratorGuardPolicy.RuleKind.LessThanOrEqual, w, bytes32(uint256(1e30)));
            _data = abi.encodePacked(_data, uint256(5e29));
        }
        vm.prank(vetro);
        guard.allowFunction(address(safe), VAULT_USDC, SEL_SETTLE, false, _rules);
        bytes32[] memory _members = new bytes32[](128);
        for (uint256 i; i < 128; ++i) _members[i] = bytes32(uint256(0x1000 + i));
        for (uint16 w = 8; w < 12; ++w) {
            vm.prank(vetro);
            guard.addAllowedValues(address(safe), VAULT_USDC, SEL_SETTLE, w, _members);
        }
        uint256 _cold = _pre(VAULT_USDC, 0, _data, Operation.Call);
        _post();
        uint256 _warm = _pre(VAULT_USDC, 0, _data, Operation.Call);
        _post();
        _log("16 rules (4 EqualTo, 4 EqualToSafe, 4 OneOf of 128, 2 floor+ceiling pairs): pre-hook, cold", _cold);
        _log("16 rules: pre-hook, warm", _warm);
        _log("16 rules: dry run, warm", _dry(VAULT_USDC, _data, Operation.Call));
        assertLt(_cold, 200_000, "16-rule pre-hook ceiling");
    }

    /// @dev A tail-hash rule over a growing payload: the hash is linear, the memory it needs is quadratic
    ///      (`keccak256` of a calldata slice copies it to memory), and the Safe's own calldata cost (16 gas
    ///      per non-zero byte) dwarfs both until the payload is far beyond anything a curator sends.
    function test_worst_case_tail_hash_over_a_long_payload() public {
        uint256[4] memory _sizes = [uint256(1 << 10), 1 << 15, 1 << 17, 1 << 18];
        _pre(VAULT_USDC, 0, navData, Operation.Call); // warm the Safe reads and the policy record
        _post();
        uint256 _previous;
        for (uint256 i; i < _sizes.length; ++i) {
            bytes memory _tail = new bytes(_sizes[i]);
            for (uint256 k; k < _tail.length; k += 97) _tail[k] = 0x5a;
            CuratorGuardPolicy.ParamRule[] memory _rules = _rule(
                CuratorGuardPolicy.RuleKind.EqualTo,
                _H().tailFlag() | 0,
                keccak256(_tail)
            );
            vm.prank(vetro);
            guard.allowFunction(address(safe), VAULT_USDC, SEL_SETTLE, false, _rules);
            bytes memory _data = abi.encodePacked(SEL_SETTLE, _tail);
            uint256 _g = _pre(VAULT_USDC, 0, _data, Operation.Call);
            _post();
            _log(string.concat("tail hash over ", vm.toString(_sizes[i]), " bytes: pre-hook, warm"), _g);
            assertGe(_g, _previous, "monotonic");
            _previous = _g;
        }
        assertLt(_previous, 3_000_000, "256 KiB tail hash stays under 3M (the Safe calldata itself costs over 4M)");
    }

    /// @dev Entries per batch: the warm slope (one allowlisted target, the `OneOf` approve) and the cold
    ///      slope (a fresh allowlisted target per entry: the function record and `EXTCODESIZE` are cold).
    function test_worst_case_batch_entries() public {
        _batchOfApproves(1); // warm the policy record, the set and the target
        uint256 _g10 = _batchOfApproves(10);
        uint256 _g50 = _batchOfApproves(50);
        uint256 _g100 = _batchOfApproves(100);
        _log("batch of 10 approve(vault, max) entries (OneOf): pre-hook", _g10);
        _log("batch of 50: pre-hook", _g50);
        _log("batch of 100: pre-hook", _g100);
        uint256 _slope = (_g100 - _g50) / 50;
        _log("  => warm slope per entry (50 -> 100)", _slope);
        assertLt(_slope, 12_000, "warm per-entry cost");
        assertLt(_g100 - _g50, 2 * (_g50 - _g10), "linear, not quadratic");
    }

    function _batchOfApproves(uint256 n_) internal returns (uint256) {
        bytes memory _packed;
        for (uint256 i; i < n_; ++i) _packed = abi.encodePacked(_packed, _entry(USDC, 0, approveData));
        uint256 _g = _pre(MULTISEND_141, 0, _multiSendCalldata(_packed), Operation.DelegateCall);
        _post();
        return _g;
    }

    /// @dev Owners per Safe: the digest hashes `getOwners()` in both hooks (a linked-list walk inside the
    ///      Safe, warm in the after-hook because the pre-hook read the same slots).
    function test_worst_case_owner_count() public {
        uint256[3] memory _counts = [uint256(4), 20, 50];
        _pre(VAULT_USDC, 0, navData, Operation.Call); // warm
        _post();
        uint256 _previousPost;
        for (uint256 i; i < _counts.length; ++i) {
            while (safe.getOwners().length < _counts[i]) _addOwner(makeAddr(string.concat("extra-owner-", vm.toString(safe.getOwners().length))));
            uint256 _g = _pre(VAULT_USDC, 0, navData, Operation.Call);
            uint256 _p = _post();
            _log(string.concat(vm.toString(_counts[i]), " owners: pre-hook updateNewTotalAssets, warm (owner slots warm too)"), _g);
            _log(string.concat(vm.toString(_counts[i]), " owners: after-hook"), _p);
            if (i > 0) _log("  => after-hook slope per owner", (_p - _previousPost) / (_counts[i] - _counts[i - 1]));
            _previousPost = _p;
        }
        assertLt(_previousPost, 120_000, "after-hook with 50 owners");
    }

    /// @dev Council window, a batch of owner-management self-calls: every entry runs the council's
    ///      allowlist check (`EXTCODESIZE` on the new owner, cold for a fresh key).
    function test_worst_case_council_window_batch_of_self_calls() public {
        vm.prank(council);
        guard.bypass(address(safe), 1 hours);
        uint256 _g10 = _councilBatch(10);
        uint256 _g50 = _councilBatch(50);
        _log("council window: batch of 10 addOwnerWithThreshold(fresh, 2) self-calls: pre-hook", _g10);
        _log("council window: batch of 50: pre-hook", _g50);
        _log("  => slope per self-call entry", (_g50 - _g10) / 40);
        assertLt((_g50 - _g10) / 40, 8_000, "per-entry cost in a council window");
    }

    function _councilBatch(uint256 n_) internal returns (uint256) {
        bytes memory _packed;
        for (uint256 i; i < n_; ++i) {
            bytes memory _call = abi.encodeCall(ISafe.addOwnerWithThreshold, (address(uint160(0x700000 + n_ * 1000 + i)), 2));
            _packed = abi.encodePacked(_packed, _entry(address(safe), 0, _call));
        }
        uint256 _g = _pre(MULTISEND_141, 0, _multiSendCalldata(_packed), Operation.DelegateCall);
        _post();
        return _g;
    }

    /// @dev An approved canonical batch is decoded at use (`ENTRY_APPROVED`: every entry kept off the
    ///      guard), after the id is recomputed over the whole payload.
    function test_worst_case_approved_batch_decode() public {
        bytes memory _packed;
        for (uint256 i; i < 50; ++i) _packed = abi.encodePacked(_packed, _entry(address(protocol), 0, abi.encodeWithSelector(SEL_SETTLE, uint256(i))));
        bytes memory _data = _multiSendCalldata(_packed);
        vm.prank(vetro);
        guard.approveTransaction(address(safe), address(0), MULTISEND_141, 0, _data, Operation.DelegateCall, 1 days);
        uint256 _g = _pre(MULTISEND_141, 0, _data, Operation.DelegateCall);
        uint256 _p = _post();
        _log("approved batch of 50 entries: pre-hook (id + handler probe + decode), warm", _g);
        _log("approved batch: after-hook (sentinel)", _p);
        assertLt(_g, 150_000, "approved 50-entry batch pre-hook");
    }
}

/// @dev The same fixture with 50 owners and 50 distinct allowlisted targets planted in `setUp` (a separate
///      transaction), so the FIRST call of each test measures those slots cold, as a real transaction does.
contract CuratorGuardG10fGasColdTest is G10fGasBase {
    bytes internal fiftyTargetsBatch;

    function setUp() public override {
        super.setUp();
        while (safe.getOwners().length < 50) _addOwner(makeAddr(string.concat("extra-owner-", vm.toString(safe.getOwners().length))));
        bytes memory _packed;
        for (uint256 i; i < 50; ++i) {
            address _t = address(uint160(0x600000 + i));
            vm.etch(_t, sinkCode);
            vm.prank(vetro);
            guard.allowFunction(address(safe), _t, SEL_SETTLE, false, _noRules());
            _packed = abi.encodePacked(_packed, _entry(_t, 0, abi.encodeWithSelector(SEL_SETTLE, uint256(i))));
        }
        fiftyTargetsBatch = _multiSendCalldata(_packed);
    }

    function test_cold_fifty_owners() public {
        uint256 _g = _pre(VAULT_USDC, 0, navData, Operation.Call);
        uint256 _p = _post();
        uint256 _g2 = _pre(VAULT_USDC, 0, navData, Operation.Call);
        uint256 _p2 = _post();
        _log("50 owners: pre-hook updateNewTotalAssets, COLD (first call of the transaction)", _g);
        _log("50 owners: after-hook, same transaction", _p);
        _log("50 owners: pre-hook, warm", _g2);
        _log("50 owners: after-hook, warm", _p2);
        assertLt(_g, 400_000, "50-owner cold pre-hook");
    }

    function test_cold_fifty_distinct_targets_in_one_batch() public {
        uint256 _g = _pre(MULTISEND_141, 0, fiftyTargetsBatch, Operation.DelegateCall);
        _post();
        uint256 _g2 = _pre(MULTISEND_141, 0, fiftyTargetsBatch, Operation.DelegateCall);
        _post();
        _log("batch of 50 entries to 50 distinct targets: pre-hook, COLD (first call of the transaction)", _g);
        _log("batch of 50 entries to 50 distinct targets: pre-hook, warm", _g2);
        _log("  => cold-minus-warm per entry", (_g - _g2) / 50);
        assertLt(_g, 1_000_000, "50 cold targets");
    }
}
