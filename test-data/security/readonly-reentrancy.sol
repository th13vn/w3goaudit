// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Deferred read-only reentrancy fixtures. The protocol-specific variants remain
// useful for future generic unsettled-phase evidence.

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
    function remove_liquidity(uint256 amount, uint256[2] calldata minAmounts) external;
    function claim_admin_fees() external;
}

interface IBalancerVault {
    function getPoolTokens(bytes32 poolId)
        external
        view
        returns (address[] memory tokens, uint256[] memory balances, uint256 lastChangeBlock);
    function manageUserBalance(bytes[] calldata ops) external;
}

interface IRateProvider {
    function getRate() external view returns (uint256);
}

library VaultReentrancyLib {
    function ensureNotInVaultContext(IBalancerVault) internal pure {}
}

contract Vulnerable_CurveReadOnlyReentrancy {
    ICurvePool public pool;

    // VULNERABLE: reads the virtual price with no reentrancy poke, so a
    // remove_liquidity callback observes an inflated value.
    function lpPrice() external view returns (uint256) {
        return pool.get_virtual_price();
    }
}

contract Safe_CurveReadOnlyReentrancy {
    ICurvePool public pool;
    uint256[2] private zero;

    // SAFE: pokes the pool's reentrancy-locked entry point first, which reverts
    // when called inside a callback.
    function lpPrice() external returns (uint256) {
        pool.remove_liquidity(0, zero);
        return pool.get_virtual_price();
    }

    // SAFE: the admin-fee claim is equally guarded by the pool's own lock.
    function lpPriceViaFees() external returns (uint256) {
        pool.claim_admin_fees();
        return pool.get_virtual_price();
    }
}

contract Vulnerable_BalancerReadOnlyReentrancy {
    IBalancerVault public vault;
    IRateProvider public rateProvider;

    // VULNERABLE: Vault composition read with no reentrancy check.
    function poolValue(bytes32 poolId) external view returns (uint256 total) {
        (, uint256[] memory balances, ) = vault.getPoolTokens(poolId);
        for (uint256 i = 0; i < balances.length; i++) {
            total += balances[i];
        }
    }

    // NOT flagged by the shipped pack: `getRate` names any rate provider, so the
    // bare name cannot identify a Balancer read. Retained here to document the
    // deliberate gap; the benchmark lane covers this shape with a pinned receiver.
    function rate() external view returns (uint256) {
        return rateProvider.getRate();
    }
}

contract Safe_BalancerReadOnlyReentrancy {
    IBalancerVault public vault;
    IRateProvider public rateProvider;

    // SAFE: ensureNotInVaultContext reverts inside the Vault's guard.
    function poolValue(bytes32 poolId) external view returns (uint256 total) {
        VaultReentrancyLib.ensureNotInVaultContext(vault);
        (, uint256[] memory balances, ) = vault.getPoolTokens(poolId);
        for (uint256 i = 0; i < balances.length; i++) {
            total += balances[i];
        }
    }

    // SAFE: same guard before the rate read.
    function rate() external view returns (uint256) {
        VaultReentrancyLib.ensureNotInVaultContext(vault);
        return rateProvider.getRate();
    }
}
