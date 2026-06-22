// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mixed real-world coding styles the builder must parse without losing the base
// list, the override targets, or the state-variable order:
//
//  1. Constructor-argument inheritance:  `is Priced(100)` — the base NAME must be
//     extracted as "Priced", with the `(100)` constructor argument ignored.
//  2. Interface inheriting multiple interfaces (interface-of-interfaces).
//  3. Abstract contract in the middle of the chain.
//  4. Explicit multi-target override:  `override(IBase, Middle)`.
//  5. State variables spread across the whole chain (storage-order check).
//
// Linearization for Vault (derived-first), solc 0.8.20:
//   Vault is Priced, Middle  (written order; last-listed Middle is most derived)
//   -> Vault -> Middle -> Priced -> Pricing -> Storage -> Base
//
// Storage-variable layout (most-base first = reverse MRO):
//   Base.baseSlot, Storage.storageSlot, Storage.balances, Pricing.priceSlot,
//   Priced.fixedPrice, Middle.middleSlot, Vault.vaultSlot

interface IRoot {
    function rootId() external view returns (uint256);
}

interface IExtra {
    function extraId() external view returns (uint256);
}

// Interface inheriting multiple interfaces.
interface ICombined is IRoot, IExtra {
    function combinedId() external view returns (uint256);
}

contract Base {
    uint256 public baseSlot;

    function tag() public virtual returns (string memory) {
        return "Base";
    }
}

contract Storage is Base {
    uint256 public storageSlot;
    mapping(address => uint256) public balances;
}

// Abstract contract in the middle — cannot be deployed but participates in MRO.
abstract contract Pricing is Storage {
    uint256 public priceSlot;

    function price() public view virtual returns (uint256);
}

// Constructor-argument base: `is Pricing` (no args) but Priced below uses args.
contract Priced is Pricing {
    uint256 public fixedPrice;

    constructor(uint256 p) {
        fixedPrice = p;
    }

    function price() public view override returns (uint256) {
        return fixedPrice;
    }
}

contract Middle is Storage {
    uint256 public middleSlot;

    function tag() public virtual override returns (string memory) {
        return "Middle";
    }
}

// Vault inherits Priced (constructor-arg base) and Middle, and multi-overrides tag().
contract Vault is Priced, Middle {
    uint256 public vaultSlot;

    constructor() Priced(100) {}

    function tag() public override(Base, Middle) returns (string memory) {
        return "Vault";
    }
}
