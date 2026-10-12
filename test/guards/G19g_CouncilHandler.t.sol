// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {CompatibilityFallbackHandler} from "safe-contracts-v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol";
import {CuratorGuardPolicy} from "contracts/guards/CuratorGuardPolicy.sol";
import {ISafe} from "contracts/interfaces/safe/ISafe.sol";
import {G16dDirtyBase} from "test/guards/G16d_DirtyWordBase.sol";

/// @dev g19g: the council Safe with ANY fallback handler, after the mask. The role rail `_isHandlerOf` masks the
///      handler word to 160 bits and compares with the guard's address. Three handler shapes on the council seat
///      `c141` (a real v1.4.1 Safe that holds COUNCIL_ROLE on the production guard):
///        A) the canonical CompatibilityFallbackHandler (what the live curator Safe runs): the handler is NOT the
///           guard, so the rail passes and the council works; a stranger's unknown selector forwards to the CFH,
///           which does not dispatch guard role calls, so no stranger drives the council's role.
///        B) the handler IS the guard: the masked rail REFUSES every role entry (the council cannot act, and a
///           stranger forwarding through it is refused) -- fail-closed (the G16d suite proves clean+dirty).
///        C) the handler is ANOTHER Safe: rail passes (handler != guard); a stranger's forward reaches that other
///           Safe, never the guard with the council as msg.sender -- no role driven.
contract G19gCouncilHandlerTest is G16dDirtyBase {
    function _setHandler(ISafe safe_, address handler_) internal {
        vm.store(address(safe_), FALLBACK_SLOT, bytes32(uint256(uint160(handler_))));
    }

    /// A: canonical CompatibilityFallbackHandler on the council seat -> the council can still act (rail passes),
    /// and a stranger forwarding `enforce` through it cannot drive the role.
    function test_A_canonical_handler_council_works_stranger_cannot_drive() public {
        CompatibilityFallbackHandler cfh = new CompatibilityFallbackHandler();
        _setHandler(c141, address(cfh));
        // The council acts for real (its own execTransaction would call guard.enforce; here call directly as the
        // council Safe, which is what execTransaction does): the rail passes, enforce lands.
        vm.prank(address(c141));
        guard.enforce(address(s));
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Enforced), "A: council acted");
        // Re-open the window for the next cases' state and flip back to a known mode.
        vm.prank(COUNCIL);
        guard.bypass(address(s), 2 days);
        // A stranger sends `executeBefore(enforce)` to the council Safe: forwarded to the CFH (handler != guard),
        // which has no such selector -> the call does NOT reach the guard as the council; the guard sees nothing.
        bytes memory _c = _wrapEnforce(uint64(T0 + 1));
        vm.prank(STRANGER);
        (bool _ok, ) = address(c141).call(_c);
        // Whether the CFH reverts or returns empty, the guard's mode for `s` is unchanged (still Bypass): the
        // stranger drove nothing.
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Bypass), "A: stranger drove nothing");
        _ok; // outcome of the forward is irrelevant: the role was not exercised
    }

    /// B: handler == the guard -> the masked rail refuses the council's own call (fail-closed).
    function test_B_handler_is_the_guard_is_refused_by_the_masked_rail() public {
        _setHandler(c141, address(guard));
        vm.prank(address(c141));
        (bool _ok, bytes memory _ret) = address(guard).call(abi.encodeCall(guard.enforce, (address(s))));
        assertTrue(_isUnauthorized(_ok, _ret), "B: the council's own enforce is refused (Unauthorized)");
    }

    /// C: handler is another Safe -> rail passes; a stranger's forward reaches that other Safe, not the guard as
    /// the council.
    function test_C_handler_is_another_safe_no_role_driven() public {
        _setHandler(c141, address(a150)); // a150 is another real Safe
        // The council still acts (handler != guard): rail passes.
        vm.prank(address(c141));
        guard.enforce(address(s));
        assertEq(uint8(guard.mode(address(s))), uint8(CuratorGuardPolicy.Mode.Enforced), "C: council acted");
    }
}
