// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

// @KeyInfo - Total Lost : 49958.06 USDT
// Attacker : 0xd99e1abfc5dd5034d7ff63828d16c5e945d1b856
// Attack Contract : 0xcc21c75f9e13054667663f9ed37f41e65b52dee7
// Vulnerable Contract : 0x1b5732eb98911c25acf7bdfaffb9409782cae6d7
// Attack Tx : https://bscscan.com/tx/0x54e120b8d62a9d7cef94bf51f1f5b8aa13565d76d8797a79afeeb25ed0e1dc25

// @Info
// Vulnerable Contract Code : https://bscscan.com/address/0x1b5732eb98911c25acf7bdfaffb9409782cae6d7#code

// @Analysis
// Twitter Guy : https://x.com/audit_911/status/2067943961327763788
//
// The attacker flash-borrowed WBNB, used it as Venus collateral, borrowed 70M USDT, and fed the USDT into
// the unverified JB helper. Repeated JB helper cycles used the live JB balance to sell/burn/sync through the
// JB/USDT pair, releasing USDT from the pair. Venus was repaid and the remaining USDT was forwarded as profit.

contract JBExploit is Test {
    function setUp() public {
        vm.createSelectFork("bsc", 12_345_678);
    }
}
