// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// Test Contracts for Slither→WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its corresponding detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// =============================================================================

// --- Interfaces used across tests ---
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// =============================================================================
// 1. REENTRANCY-ETH — External call before state write, no guard
// =============================================================================

// SHOULD TRIGGER: reentrancy-eth
contract Vulnerable_ReentrancyEth {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // BAD: external call before state update, no reentrancy guard
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // state write AFTER external call
    }
}

// SHOULD NOT TRIGGER: reentrancy-eth
contract Safe_ReentrancyEth {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: has nonReentrant guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount; // state write BEFORE external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// =============================================================================
// 2. ARBITRARY-SEND-ERC20 — transferFrom with user-controlled 'from'
// =============================================================================

// SHOULD TRIGGER: arbitrary-send-erc20
contract Vulnerable_ArbitrarySendERC20 {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: 'from' is user-controlled parameter, no auth
    function steal(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }
}

// SHOULD NOT TRIGGER: arbitrary-send-erc20
contract Safe_ArbitrarySendERC20 {
    IERC20 public token;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(IERC20 _token) {
        token = _token;
        owner = msg.sender;
    }

    // SAFE: has onlyOwner modifier
    function adminTransfer(address from, address to, uint256 amount) external onlyOwner {
        token.transferFrom(from, to, amount);
    }

    // SAFE: uses msg.sender as from
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
    }
}

// =============================================================================
// 3. CONTROLLED-DELEGATECALL — delegatecall with user-controlled target
// =============================================================================

// SHOULD TRIGGER: controlled-delegatecall
contract Vulnerable_ControlledDelegatecall {
    // BAD: delegatecall target from parameter
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// SHOULD NOT TRIGGER: controlled-delegatecall
contract Safe_ControlledDelegatecall {
    address public immutable implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    // SAFE: delegatecall to fixed implementation, not parameter
    function execute(bytes calldata data) external {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// =============================================================================
// 4. SUICIDAL — Unprotected selfdestruct
// =============================================================================

// SHOULD TRIGGER: suicidal
contract Vulnerable_Suicidal {
    // BAD: anyone can destroy this contract
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

// SHOULD NOT TRIGGER: suicidal
contract Safe_Suicidal {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // SAFE: only owner can destroy
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}

// =============================================================================
// 5. ARBITRARY-SEND-ETH — ETH transfer without auth
// =============================================================================

// SHOULD TRIGGER: arbitrary-send-eth
contract Vulnerable_ArbitrarySendEth {
    // BAD: anyone can drain ETH
    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}

// SHOULD NOT TRIGGER: arbitrary-send-eth
contract Safe_ArbitrarySendEth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // SAFE: restricted to owner
    function withdraw(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}

// =============================================================================
// 6. MSG-VALUE-LOOP — msg.value used inside a loop
// =============================================================================

// SHOULD TRIGGER: msg-value-loop
contract Vulnerable_MsgValueLoop {
    mapping(address => uint256) public balances;

    // BAD: msg.value reused in each iteration
    function batchDeposit(address[] calldata receivers) external payable {
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += msg.value; // Same msg.value each iter!
        }
    }
}

// SHOULD NOT TRIGGER: msg-value-loop
contract Safe_MsgValueLoop {
    mapping(address => uint256) public balances;

    // SAFE: explicit amounts array, sum validated
    function batchDeposit(address[] calldata receivers, uint256[] calldata amounts) external payable {
        uint256 total = 0;
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += amounts[i];
            total += amounts[i];
        }
        require(total == msg.value, "Amount mismatch");
    }
}

// =============================================================================
// 7. DELEGATECALL-LOOP — delegatecall inside a loop
// =============================================================================

// SHOULD TRIGGER: delegatecall-loop
contract Vulnerable_DelegatecallLoop {
    // BAD: delegatecall in loop
    function multicall(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, ) = target.delegatecall(data[i]);
            require(success, "Failed");
        }
    }
}

// SHOULD NOT TRIGGER: delegatecall-loop
contract Safe_DelegatecallLoop {
    // SAFE: regular call in loop instead of delegatecall
    function multicall(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, ) = target.call(data[i]);
            require(success, "Failed");
        }
    }
}

// =============================================================================
// 8. UNCHECKED-TRANSFER — ERC20 transfer return value not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-transfer
contract Vulnerable_UncheckedTransfer {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: return value of transfer not checked
    function pay(address to, uint256 amount) external {
        token.transfer(to, amount); // return value ignored!
    }

    // BAD: return value of transferFrom not checked
    function collect(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount); // return value ignored!
    }
}

// SHOULD NOT TRIGGER: unchecked-transfer
contract Safe_UncheckedTransfer {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: return value checked with require
    function pay(address to, uint256 amount) external {
        require(token.transfer(to, amount), "Transfer failed");
    }

    // SAFE: return value checked in if
    function collect(address from, uint256 amount) external {
        if (!token.transferFrom(from, address(this), amount)) {
            revert("TransferFrom failed");
        }
    }
}

// =============================================================================
// 9. WEAK-PRNG — Block variables used for randomness
// =============================================================================

// SHOULD TRIGGER: weak-prng
contract Vulnerable_WeakPRNG {
    // BAD: block.timestamp used with modulo for randomness
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp))) % 100;
    }

    // BAD: block.number used for randomness
    function random2() external view returns (uint256) {
        return block.number % 10;
    }
}

// SHOULD NOT TRIGGER: weak-prng
contract Safe_WeakPRNG {
    uint256 private seed;

    // SAFE: no modulo on block variables
    function getTimestamp() external view returns (uint256) {
        return block.timestamp; // just reading, not using for randomness
    }
}

// =============================================================================
// 10. UNPROTECTED-UPGRADE — initialize without auth
// =============================================================================

// SHOULD TRIGGER: unprotected-upgrade
contract Vulnerable_UnprotectedUpgrade {
    address public owner;
    bool public initialized;

    // BAD: anyone can call initialize and take ownership
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
}

// SHOULD NOT TRIGGER: unprotected-upgrade
contract Safe_UnprotectedUpgrade {
    address public owner;
    bool public initialized;

    modifier onlyAdmin() {
        require(msg.sender == owner, "Not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SAFE: onlyAdmin modifier protects initialization
    function initialize(address _newOwner) external onlyAdmin {
        require(!initialized, "Already initialized");
        owner = _newOwner;
        initialized = true;
    }
}

// =============================================================================
// 11. INCORRECT-EXP — ^ (XOR) instead of ** (exponentiation)
// =============================================================================

// SHOULD TRIGGER: incorrect-exp
contract Vulnerable_IncorrectExp {
    // BAD: ^ is XOR, not exponentiation; 2^8 = 10, not 256
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ^ exp;
    }
}

// SHOULD NOT TRIGGER: incorrect-exp
contract Safe_IncorrectExp {
    // SAFE: using ** for exponentiation
    function power(uint256 base, uint256 exp) external pure returns (uint256) {
        return base ** exp;
    }
}

// =============================================================================
// 12. REENTRANCY-BALANCE — balanceOf before external call
// =============================================================================

// SHOULD TRIGGER: reentrancy-balance
contract Vulnerable_ReentrancyBalance {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: balance read before external call, no guard
    function mint(uint256 amountToPay) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        // Attacker can reenter via this callback
        ICallback(msg.sender).pay(amountToPay);
        require(token.balanceOf(address(this)) - balanceBefore >= amountToPay, "Underpaid");
    }
}

interface ICallback {
    function pay(uint256 amount) external;
}

// SHOULD NOT TRIGGER: reentrancy-balance
contract Safe_ReentrancyBalance {
    IERC20 public token;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: nonReentrant guard
    function mint(uint256 amountToPay) external nonReentrant {
        uint256 balanceBefore = token.balanceOf(address(this));
        ICallback(msg.sender).pay(amountToPay);
        require(token.balanceOf(address(this)) - balanceBefore >= amountToPay, "Underpaid");
    }
}

// =============================================================================
// 13. REENTRANCY-NO-ETH — External call before state write (no ETH)
// =============================================================================

// SHOULD TRIGGER: reentrancy-no-eth
contract Vulnerable_ReentrancyNoEth {
    IERC20 public token;
    mapping(address => bool) public claimed;

    constructor(IERC20 _token) {
        token = _token;
    }

    // BAD: external call before state update, no guard
    function claim() external {
        require(!claimed[msg.sender], "Already claimed");
        token.transfer(msg.sender, 100e18); // external call
        claimed[msg.sender] = true; // state write after call
    }
}

// SHOULD NOT TRIGGER: reentrancy-no-eth
contract Safe_ReentrancyNoEth {
    IERC20 public token;
    mapping(address => bool) public claimed;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: state written before external call (CEI)
    function claim() external {
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true; // state write BEFORE call
        token.transfer(msg.sender, 100e18);
    }
}

// =============================================================================
// 14. UNCHECKED-LOWLEVEL — Low-level call return not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-lowlevel
contract Vulnerable_UncheckedLowLevel {
    // BAD: low-level call return value ignored
    function sendEther(address payable to) external payable {
        to.call{value: msg.value}(""); // return value not checked!
    }
}

// SHOULD NOT TRIGGER: unchecked-lowlevel
contract Safe_UncheckedLowLevel {
    // SAFE: return value checked
    function sendEther(address payable to) external payable {
        (bool success, ) = to.call{value: msg.value}("");
        require(success, "Call failed");
    }
}

// =============================================================================
// 15. UNCHECKED-SEND — send() return not checked
// =============================================================================

// SHOULD TRIGGER: unchecked-send
contract Vulnerable_UncheckedSend {
    // BAD: send return value ignored
    function pay(address payable to, uint256 amount) external {
        to.send(amount); // return value not checked!
    }
}

// SHOULD NOT TRIGGER: unchecked-send
contract Safe_UncheckedSend {
    // SAFE: return value checked
    function pay(address payable to, uint256 amount) external {
        require(to.send(amount), "Send failed");
    }
}

// =============================================================================
// 16. TX-ORIGIN — tx.origin used for authorization
// =============================================================================

// SHOULD TRIGGER: tx-origin
contract Vulnerable_TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BAD: tx.origin used for auth check
    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// SHOULD NOT TRIGGER: tx-origin
contract Safe_TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: msg.sender used for auth
    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// =============================================================================
// 17. INCORRECT-EQUALITY — Strict equality on balance
// =============================================================================

// SHOULD TRIGGER: incorrect-equality
contract Vulnerable_IncorrectEquality {
    // BAD: strict equality on balance — can be broken by forced ETH send
    function goalReached() external view returns (bool) {
        return address(this).balance == 100 ether;
    }
}

// SHOULD NOT TRIGGER: incorrect-equality
contract Safe_IncorrectEquality {
    // SAFE: uses >= instead of ==
    function goalReached() external view returns (bool) {
        return address(this).balance >= 100 ether;
    }
}

// =============================================================================
// 18. DIVIDE-BEFORE-MULTIPLY — Precision loss
// =============================================================================

// SHOULD TRIGGER: divide-before-multiply
contract Vulnerable_DivideBeforeMultiply {
    // BAD: division before multiplication causes truncation
    function calculate(uint256 supply, uint256 n, uint256 interest) external pure returns (uint256) {
        return (supply / n) * interest;
    }
}

// SHOULD NOT TRIGGER: divide-before-multiply
contract Safe_DivideBeforeMultiply {
    // SAFE: multiplication before division
    function calculate(uint256 supply, uint256 n, uint256 interest) external pure returns (uint256) {
        return (supply * interest) / n;
    }
}

// =============================================================================
// 19. BOOLEAN-CST — Boolean constant misuse
// =============================================================================

// SHOULD TRIGGER: boolean-cst
contract Vulnerable_BooleanCst {
    uint256 public x;

    // BAD: boolean constant in condition — dead code
    function badFunc(uint256 val) external {
        if (false) {
            x = val; // dead code
        }
    }

    // BAD: boolean constant makes expression always true
    function alwaysTrue(bool b) external pure returns (bool) {
        if (true) {
            return b;
        }
        return false;
    }
}

// SHOULD NOT TRIGGER: boolean-cst
contract Safe_BooleanCst {
    uint256 public x;

    // SAFE: real condition
    function goodFunc(uint256 val) external {
        if (val > 0) {
            x = val;
        }
    }
}

// =============================================================================
// 20. CONSTANT-FUNCTION-STATE — view/pure function modifies state
// =============================================================================

// SHOULD TRIGGER: constant-function-state
contract Vulnerable_ConstantFunctionState {
    uint256 public counter;

    // BAD: declared view but modifies state (won't compile in >= 0.5 but
    // illustrates the pattern for pre-0.5 contracts)
    // Note: This won't actually compile in ^0.8.0 due to compiler enforcement.
    // For testing purposes, we use a workaround with assembly.
    function get() public view returns (uint256) {
        // Workaround: assembly bypasses view restriction
        assembly {
            sstore(0, add(sload(0), 1))
        }
        return counter;
    }
}

// SHOULD NOT TRIGGER: constant-function-state
contract Safe_ConstantFunctionState {
    uint256 public counter;

    // SAFE: view function only reads state
    function get() public view returns (uint256) {
        return counter;
    }

    // SAFE: non-view function modifies state
    function increment() public {
        counter += 1;
    }
}

// =============================================================================
// 21. REENTRANCY-EVENTS — External call before event emission
// =============================================================================

// SHOULD TRIGGER: reentrancy-events
contract Vulnerable_ReentrancyEvents {
    event Withdrawal(address indexed user, uint256 amount);
    mapping(address => uint256) public balances;

    // BAD: event emitted AFTER external call — can be reordered via reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        emit Withdrawal(msg.sender, amount); // event AFTER call
    }
}

// SHOULD NOT TRIGGER: reentrancy-events
contract Safe_ReentrancyEvents {
    event Withdrawal(address indexed user, uint256 amount);
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    // SAFE: has nonReentrant guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
    }
}

// =============================================================================
// 22. CALLS-LOOP — External calls inside loop (DoS risk)
// =============================================================================

// SHOULD TRIGGER: calls-loop
contract Vulnerable_CallsLoop {
    address[] public recipients;

    // BAD: external call in loop — single failure blocks all
    function distributeEther() external payable {
        uint256 share = msg.value / recipients.length;
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(share); // if one reverts, all fail
        }
    }
}

// SHOULD NOT TRIGGER: calls-loop
contract Safe_CallsLoop {
    mapping(address => uint256) public pendingWithdrawals;

    // SAFE: pull pattern — no external calls in loop
    function recordDistribution(address[] calldata addrs, uint256 amount) external {
        for (uint256 i = 0; i < addrs.length; i++) {
            pendingWithdrawals[addrs[i]] += amount;
        }
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

// =============================================================================
// 23. COSTLY-LOOP — State variable update inside loop
// =============================================================================

// SHOULD TRIGGER: costly-loop
contract Vulnerable_CostlyLoop {
    uint256 public totalBalance;
    mapping(address => uint256) public balances;

    // BAD: state variable updated in every loop iteration (expensive SSTORE)
    function updateBalances(address[] calldata users, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = amounts[i];
            totalBalance += amounts[i]; // SSTORE in each iteration!
        }
    }
}

// SHOULD NOT TRIGGER: costly-loop
contract Safe_CostlyLoop {
    uint256 public totalBalance;
    mapping(address => uint256) public balances;

    // SAFE: accumulate in memory, single state write after loop
    function updateBalances(address[] calldata users, uint256[] calldata amounts) external {
        uint256 tempTotal = 0;
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = amounts[i];
            tempTotal += amounts[i]; // memory variable
        }
        totalBalance += tempTotal; // single SSTORE
    }
}

// =============================================================================
// 24. TIMESTAMP — block.timestamp used in comparison
// =============================================================================

// SHOULD TRIGGER: timestamp
contract Vulnerable_Timestamp {
    uint256 public unlockTime;

    constructor(uint256 _unlockTime) {
        unlockTime = _unlockTime;
    }

    // Detectable: block.timestamp in require condition
    function withdraw() external {
        require(block.timestamp >= unlockTime, "Too early");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// SHOULD NOT TRIGGER: timestamp
contract Safe_Timestamp {
    // SAFE: block.timestamp not used in comparison
    function getTime() external view returns (uint256) {
        return block.number;
    }
}

// =============================================================================
// 25. ASSERT-STATE-CHANGE — State change inside assert()
// =============================================================================

// SHOULD TRIGGER: assert-state-change
contract Vulnerable_AssertStateChange {
    uint256 public counter;
    mapping(address => uint256) public nonces;

    // BAD: state change inside assert — optimizer may remove it
    function processWithAssert(address user) external {
        assert(incrementNonce(user));
    }

    function incrementNonce(address user) internal returns (bool) {
        nonces[user] += 1;
        return true;
    }
}

// SHOULD NOT TRIGGER: assert-state-change
contract Safe_AssertStateChange {
    uint256 public counter;

    // SAFE: assert only checks invariant, no state change
    function process(uint256 x) external {
        counter += x;
        assert(counter >= x); // pure invariant check
    }
}

// =============================================================================
// 26. ASSEMBLY — Inline assembly usage
// =============================================================================

// SHOULD TRIGGER: assembly
contract Vulnerable_Assembly {
    // Has inline assembly
    function getBalance(address addr) external view returns (uint256 bal) {
        assembly {
            bal := balance(addr)
        }
    }
}

// SHOULD NOT TRIGGER: assembly
contract Safe_Assembly {
    // SAFE: no assembly
    function getBalance(address addr) external view returns (uint256) {
        return addr.balance;
    }
}

// =============================================================================
// 27. LOW-LEVEL-CALLS — Low-level call usage
// =============================================================================

// SHOULD TRIGGER: low-level-calls
contract Vulnerable_LowLevelCalls {
    // Has low-level call
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool success, bytes memory result) = target.call(data);
        require(success, "Failed");
        return result;
    }
}

// SHOULD NOT TRIGGER: low-level-calls
contract Safe_LowLevelCalls {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    // SAFE: high-level call via interface
    function execute(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}

// =============================================================================
// 28. SOLC-VERSION — Outdated Solidity version
// =============================================================================
// NOTE: This file uses ^0.8.0, so the solc-version template (which checks
// for <0.8.0) should NOT trigger on this file. A separate pre-0.8 file
// would be needed to test the positive case.
// The detector is included for completeness — it filters by pragma version.
