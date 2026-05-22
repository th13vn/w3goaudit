// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// TEST CONTRACT: 4naly3er → WQL Template Verification
// Each Vulnerable_* contract SHOULD trigger its detector.
// Each Safe_* contract SHOULD NOT trigger the detector.
// Total: 37 detectors × 2 patterns = 74 contracts
// =============================================================================

// ─── Shared Interfaces & Mocks ───────────────────────────────────────────────

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IChainlinkAggregator {
    function latestAnswer() external view returns (int256);
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    );
}

interface IWstETH {
    function stEthPerToken() external view returns (uint256);
}

// SafeERC20 stub for safe tests
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "safeTransfer failed");
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount), "safeTransferFrom failed");
    }
    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        token.approve(spender, amount);
    }
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 amount) internal {
        token.approve(spender, amount);
    }
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        token.approve(spender, 0);
        token.approve(spender, value);
    }
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Malleable");
        return ecrecover(hash, v, r, s);
    }
}

// =============================================================================
// ── H-001: COMPARISON OUTSIDE CONDITION ──────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: H-comparison-outside-condition
contract Vulnerable_ComparisonOutsideCondition {
    uint256 public value;

    // BAD: comparison result discarded — this does nothing
    function setValue(uint256 newVal) external {
        value = newVal;
        value == 100; // bare comparison, silently ignored
    }
}

// SHOULD NOT TRIGGER
contract Safe_ComparisonOutsideCondition {
    uint256 public value;

    function setValue(uint256 newVal) external {
        value = newVal;
        require(value <= 1000, "Too large");
    }
}

// =============================================================================
// ── H-002: DELEGATECALL IN LOOP ──────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: H-delegatecall-in-loop
contract Vulnerable_DelegateCallInLoop {
    function multiExecute(address target, bytes[] calldata data) external {
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok,) = target.delegatecall(data[i]); // delegatecall in loop
            require(ok, "Failed");
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_DelegateCallInLoop {
    address public impl;
    constructor(address _impl) { impl = _impl; }

    // Single delegatecall, not in a loop
    function execute(bytes calldata data) external {
        (bool ok,) = impl.delegatecall(data);
        require(ok, "Failed");
    }
}

// =============================================================================
// ── H-003: MSG.VALUE IN LOOP ─────────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: H-msg-value-in-loop
contract Vulnerable_MsgValueInLoop {
    mapping(address => uint256) public shares;

    function batchDeposit(address[] calldata users) external payable {
        for (uint256 i = 0; i < users.length; i++) {
            shares[users[i]] += msg.value; // msg.value reused per iteration!
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_MsgValueInLoop {
    mapping(address => uint256) public shares;

    function batchDeposit(address[] calldata users, uint256[] calldata amounts) external payable {
        uint256 total;
        for (uint256 i = 0; i < users.length; i++) {
            shares[users[i]] += amounts[i];
            total += amounts[i];
        }
        require(total == msg.value, "Amount mismatch");
    }
}

// =============================================================================
// ── H-004: WSTETH PRICE USING STETHPERTOKEN ──────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: H-wsteth-price-steth
contract Vulnerable_WstEthPrice {
    IWstETH public wstETH;

    constructor(IWstETH _wst) { wstETH = _wst; }

    // BAD: multiplying ETH price by stEthPerToken (stETH units, not ETH)
    function getWstEthPrice(uint256 ethPrice) external view returns (uint256) {
        return ethPrice * wstETH.stEthPerToken(); // stEthPerToken != ETH ratio
    }
}

// SHOULD NOT TRIGGER
contract Safe_WstEthPrice {
    IWstETH public wstETH;

    constructor(IWstETH _wst) { wstETH = _wst; }

    // SAFE: just reading stEthPerToken without multiplying by price
    function getConversionRate() external view returns (uint256) {
        return wstETH.stEthPerToken();
    }
}

// =============================================================================
// ── M-001: TX.ORIGIN AUTHORIZATION ───────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-avoid-tx-origin
contract Vulnerable_TxOrigin {
    address public owner;
    constructor() { owner = msg.sender; }

    function withdraw() external {
        require(tx.origin == owner, "Not owner"); // tx.origin in require
        payable(msg.sender).transfer(address(this).balance);
    }
}

// SHOULD NOT TRIGGER
contract Safe_TxOrigin {
    address public owner;
    constructor() { owner = msg.sender; }

    function withdraw() external {
        require(msg.sender == owner, "Not owner"); // uses msg.sender
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}

// =============================================================================
// ── M-002: CENTRALIZATION RISK ───────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-centralization-risk
contract Vulnerable_CentralizationRisk {
    address public owner;
    uint256 public fee;
    IERC20 public token;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(IERC20 _token) {
        owner = msg.sender;
        token = _token;
    }

    // Privileged state write — centralization risk
    function setFee(uint256 _fee) external onlyOwner {
        fee = _fee;
    }

    function drainTo(address to, uint256 amount) external onlyOwner {
        token.transfer(to, amount);
    }
}

// SHOULD NOT TRIGGER (no privileged modifier on state writes)
contract Safe_CentralizationRisk {
    uint256 public constant FEE = 100; // immutable fee, no admin

    function getFee() external pure returns (uint256) {
        return FEE;
    }
}

// =============================================================================
// ── M-003: DEPRECATED CHAINLINK latestAnswer() ───────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-deprecated-chainlink-latest-answer
contract Vulnerable_DeprecatedChainlink {
    IChainlinkAggregator public feed;
    constructor(IChainlinkAggregator _feed) { feed = _feed; }

    // BAD: using deprecated latestAnswer()
    function getPrice() external view returns (int256) {
        return feed.latestAnswer(); // deprecated — returns 0 silently on failure
    }
}

// SHOULD NOT TRIGGER
contract Safe_DeprecatedChainlink {
    IChainlinkAggregator public feed;
    uint256 public constant STALE_PERIOD = 1 hours;

    constructor(IChainlinkAggregator _feed) { feed = _feed; }

    function getPrice() external view returns (int256 answer) {
        uint80 roundId;
        uint256 updatedAt;
        uint80 answeredInRound;
        (, answer,, updatedAt, answeredInRound) = feed.latestRoundData();
        require(answer > 0, "Invalid price");
        require(updatedAt >= block.timestamp - STALE_PERIOD, "Stale price");
        require(answeredInRound >= roundId, "Stale round");
    }
}

// =============================================================================
// ── M-004: STALE ORACLE DATA ─────────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-stale-oracle-data
contract Vulnerable_StaleOracleData {
    IChainlinkAggregator public feed;
    constructor(IChainlinkAggregator _feed) { feed = _feed; }

    // BAD: latestRoundData called but staleness not checked
    function getPrice() external view returns (int256 price) {
        (,price,,,) = feed.latestRoundData(); // no updatedAt / answeredInRound check
    }
}

// SHOULD NOT TRIGGER
contract Safe_StaleOracleData {
    IChainlinkAggregator public feed;
    uint256 public constant MAX_DELAY = 3600;

    constructor(IChainlinkAggregator _feed) { feed = _feed; }

    function getPrice() external view returns (int256 price) {
        uint80 roundId;
        uint256 updatedAt;
        uint80 answeredInRound;
        (, price,, updatedAt, answeredInRound) = feed.latestRoundData();
        require(price > 0, "Bad price");
        require(updatedAt >= block.timestamp - MAX_DELAY, "Stale updatedAt");
        require(answeredInRound >= roundId, "Stale answeredInRound");
    }
}

// =============================================================================
// ── M-005: APPROVE WITHOUT ZERO FIRST ────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-approve-zero-first
contract Vulnerable_ApproveZeroFirst {
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // BAD: direct approve without zeroing first
    function approveSpender(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

// SHOULD NOT TRIGGER
contract Safe_ApproveZeroFirst {
    using SafeERC20 for IERC20;
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // SAFE: first sets to 0, then to new value
    function approveSpender(address spender, uint256 amount) external {
        token.forceApprove(token, spender, amount);
    }
}

// =============================================================================
// ── M-006: UNCHECKED ERC20 TRANSFER ─────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-unchecked-erc20-transfer
contract Vulnerable_UncheckedERC20Transfer {
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // BAD: return value of transfer ignored
    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}

// SHOULD NOT TRIGGER
contract Safe_UncheckedERC20Transfer {
    using SafeERC20 for IERC20;
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // SAFE: uses SafeERC20 which reverts on false
    function pay(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }
}

// =============================================================================
// ── M-007: BLOCK.NUMBER ON L2 ────────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-block-number-l2
contract Vulnerable_BlockNumberL2 {
    mapping(address => uint256) public lastBlock;

    function cooldown(address user) external {
        require(block.number > lastBlock[user] + 100, "Cooldown"); // block.number in require
        lastBlock[user] = block.number;
    }
}

// SHOULD NOT TRIGGER
contract Safe_BlockNumberL2 {
    mapping(address => uint256) public lastTime;

    function cooldown(address user) external {
        require(block.timestamp > lastTime[user] + 1 hours, "Cooldown"); // uses timestamp
        lastTime[user] = block.timestamp;
    }
}

// =============================================================================
// ── M-008: ERC721 _mint() INSTEAD OF _safeMint() ─────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-erc721-safe-mint
contract Vulnerable_ERC721SafeMint {
    mapping(uint256 => address) public owners;
    uint256 public nextId;

    // BAD: internal _mint without ERC721Receiver check
    function _mint(address to, uint256 tokenId) internal {
        owners[tokenId] = to;
    }

    function mint(address to) external {
        _mint(to, nextId++);
    }
}

// SHOULD NOT TRIGGER (uses _safeMint)
contract Safe_ERC721SafeMint {
    mapping(uint256 => address) public owners;
    uint256 public nextId;

    function _safeMint(address to, uint256 tokenId) internal {
        owners[tokenId] = to;
        // Would check IERC721Receiver in real impl
    }

    function mint(address to) external {
        _safeMint(to, nextId++);
    }
}

// =============================================================================
// ── M-009: ERC721 transferFrom INSTEAD OF safeTransferFrom ───────────────────
// =============================================================================

// SHOULD TRIGGER: M-erc721-safe-transfer-from
contract Vulnerable_ERC721SafeTransferFrom {
    IERC721 public nft;
    constructor(IERC721 _nft) { nft = _nft; }

    // BAD: uses transferFrom, skips ERC721Receiver check
    function sendNFT(address to, uint256 tokenId) external {
        nft.transferFrom(address(this), to, tokenId);
    }
}

// SHOULD NOT TRIGGER
contract Safe_ERC721SafeTransferFrom {
    IERC721 public nft;
    constructor(IERC721 _nft) { nft = _nft; }

    // SAFE: uses safeTransferFrom
    function sendNFT(address to, uint256 tokenId) external {
        nft.safeTransferFrom(address(this), to, tokenId);
    }
}

// =============================================================================
// ── M-010: FEE OVER 100% ─────────────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: M-fee-over-100
contract Vulnerable_FeeOver100 {
    address public owner;
    uint256 public fee; // fee in BPS, should be <= 10000

    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor() { owner = msg.sender; }

    // BAD: no upper bound check — owner can set fee to 100000 (1000%)
    function setFee(uint256 _fee) external onlyOwner {
        fee = _fee;
    }
}

// SHOULD NOT TRIGGER
contract Safe_FeeOver100 {
    address public owner;
    uint256 public fee;
    uint256 public constant MAX_FEE = 1000; // 10% in BPS

    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor() { owner = msg.sender; }

    // SAFE: validates fee <= MAX_FEE
    function setFee(uint256 _fee) external onlyOwner {
        require(_fee <= MAX_FEE, "Fee exceeds max");
        fee = _fee;
    }
}

// =============================================================================
// ── L-001: SINGLE-STEP OWNERSHIP TRANSFER ────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-2step-ownership
contract Vulnerable_TwoStepOwner {
    address public owner;
    constructor() { owner = msg.sender; }

    // BAD: one-step transfer — typo could permanently lose ownership
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }
}

// SHOULD NOT TRIGGER
contract Safe_TwoStepOwner {
    address public owner;
    address public pendingOwner;

    constructor() { owner = msg.sender; }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        pendingOwner = newOwner; // two-step: just sets pending
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}

// =============================================================================
// ── L-002: MISSING address(0) CHECK ─────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-address-zero-check
contract Vulnerable_AddressZeroCheck {
    address public treasury;

    // BAD: no check for address(0) before storing
    function setTreasury(address _treasury) external {
        treasury = _treasury;
    }
}

// SHOULD NOT TRIGGER
contract Safe_AddressZeroCheck {
    address public treasury;

    function setTreasury(address _treasury) external {
        require(_treasury != address(0), "Zero address");
        treasury = _treasury;
    }
}

// =============================================================================
// ── L-003: DIRECT ecrecover() USAGE ─────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-avoid-ecrecover
contract Vulnerable_Ecrecover {
    // BAD: raw ecrecover — susceptible to signature malleability
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}

// SHOULD NOT TRIGGER
contract Safe_Ecrecover {
    using ECDSA for bytes32;

    // SAFE: uses ECDSA library with malleability check
    function verify(bytes32 hash, bytes memory sig) external pure returns (address) {
        return hash.recover(sig);
    }
}

// =============================================================================
// ── L-004: abi.encodePacked() WITH DYNAMIC TYPES ─────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-avoid-encode-packed
contract Vulnerable_EncodePacked {
    // BAD: encodePacked with two strings — hash collision possible
    function hashPair(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}

// SHOULD NOT TRIGGER
contract Safe_EncodePacked {
    // SAFE: abi.encode pads to 32 bytes, prevents collision
    function hashPair(string memory a, string memory b) external pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }
}

// =============================================================================
// ── L-005: DEPRECATED ERC20 approve() ────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-deprecated-approve
contract Vulnerable_DeprecatedApprove {
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // BAD: direct approve susceptible to front-running
    function setAllowance(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

// SHOULD NOT TRIGGER
contract Safe_DeprecatedApprove {
    using SafeERC20 for IERC20;
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // SAFE: uses safeIncreaseAllowance
    function setAllowance(address spender, uint256 amount) external {
        token.safeIncreaseAllowance(spender, amount);
    }
}

// =============================================================================
// ── L-006: DEPRECATED safeApprove() ─────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-deprecated-safe-approve
contract Vulnerable_DeprecatedSafeApprove {
    using SafeERC20 for IERC20;
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // BAD: safeApprove is deprecated
    function approveRouter(address router, uint256 amount) external {
        token.safeApprove(router, amount);
    }
}

// SHOULD NOT TRIGGER
contract Safe_DeprecatedSafeApprove {
    using SafeERC20 for IERC20;
    IERC20 public token;
    constructor(IERC20 _token) { token = _token; }

    // SAFE: uses forceApprove (OZ v5)
    function approveRouter(address router, uint256 amount) external {
        token.forceApprove(token, router, amount);
    }
}

// =============================================================================
// ── L-007: IMPL CONTRACT WITHOUT _disableInitializers() CALL ─────────────────
// =============================================================================

// SHOULD TRIGGER: L-disable-init-impl
contract Vulnerable_DisableInitImpl {
    address public owner;
    bool public initialized;

    // BAD: no constructor with _disableInitializers()
    // Anyone can call initialize() on the implementation directly
    function initialize(address _owner) external {
        require(!initialized, "Already init");
        owner = _owner;
        initialized = true;
    }
}

// SHOULD NOT TRIGGER (has a guarded initializer or proper protection)
contract Safe_DisableInitImpl {
    address public owner;
    bool public initialized;
    bool private _initializersDisabled;

    constructor() {
        _initializersDisabled = true; // simulates _disableInitializers()
    }

    function initialize(address _owner) external {
        require(!_initializersDisabled, "Disabled");
        require(!initialized, "Already init");
        owner = _owner;
        initialized = true;
    }
}

// =============================================================================
// ── L-008: UNSAFE TYPE CASTING ───────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-unsafe-casting
contract Vulnerable_UnsafeCasting {
    // BAD: downcasting uint256→uint128 without overflow check
    function store(uint256 bigValue) external pure returns (uint128) {
        return uint128(bigValue); // silently truncates upper 128 bits
    }
}

// SHOULD NOT TRIGGER (uses SafeCast-like check)
contract Safe_UnsafeCasting {
    error Overflow();

    function store(uint256 bigValue) external pure returns (uint128) {
        if (bigValue > type(uint128).max) revert Overflow();
        return uint128(bigValue);
    }
}

// =============================================================================
// ── L-009: EXTERNAL CALLS IN LOOP ────────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-ext-call-loop
contract Vulnerable_ExtCallLoop {
    address[] public recipients;

    function distribute(uint256 share) external payable {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(share); // external call in loop
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_ExtCallLoop {
    mapping(address => uint256) public pending;

    // SAFE: pull pattern — no external call in loop
    function record(address[] calldata users, uint256 share) external {
        for (uint256 i = 0; i < users.length; i++) {
            pending[users[i]] += share;
        }
    }

    function claim() external {
        uint256 amount = pending[msg.sender];
        pending[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

// =============================================================================
// ── L-010: DIVISION WITHOUT ZERO CHECK ───────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-div0-not-prevented
contract Vulnerable_Div0NotPrevented {
    // BAD: no require(b > 0) before dividing
    function divide(uint256 a, uint256 b) external pure returns (uint256) {
        return a / b; // panics if b == 0
    }
}

// SHOULD NOT TRIGGER
contract Safe_Div0NotPrevented {
    function divide(uint256 a, uint256 b) external pure returns (uint256) {
        require(b > 0, "Division by zero");
        return a / b;
    }
}

// =============================================================================
// ── L-011: DEADLINE USING block.number INSTEAD OF block.timestamp ─────────────
// =============================================================================

// SHOULD TRIGGER: L-include-timestamp-at-deadline
contract Vulnerable_TimestampDeadline {
    mapping(address => uint256) public lastActionBlock;

    // BAD: uses block.number for deadline — unreliable on L2
    function executeWithDeadline(address user, uint256 deadlineBlock) external {
        require(block.number <= deadlineBlock, "Past deadline"); // block.number in require
        lastActionBlock[user] = block.number;
    }
}

// SHOULD NOT TRIGGER
contract Safe_TimestampDeadline {
    mapping(address => uint256) public lastActionTime;

    function executeWithDeadline(address user, uint256 deadline) external {
        require(block.timestamp <= deadline, "Past deadline"); // timestamp
        lastActionTime[user] = block.timestamp;
    }
}

// =============================================================================
// ── L-012: MINT/BURN WITHOUT address(0) CHECK ────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-mint-burn-address-zero
contract Vulnerable_MintBurnZero {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // BAD: mint to address(0) possible
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }

    // BAD: burn from address(0) possible
    function burn(address from, uint256 amount) external {
        balances[from] -= amount;
        totalSupply -= amount;
    }
}

// SHOULD NOT TRIGGER
contract Safe_MintBurnZero {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        require(to != address(0), "Mint to zero");
        balances[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external {
        require(from != address(0), "Burn from zero");
        balances[from] -= amount;
        totalSupply -= amount;
    }
}

// =============================================================================
// ── L-013: DEPRECATED _setupRole() ──────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: L-deprecated-setup-role
contract Vulnerable_DeprecatedSetupRole {
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // BAD: _setupRole is deprecated, should use _grantRole
    function _setupRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    function giveRole(bytes32 role, address account) external {
        _setupRole(role, account);
    }
}

// SHOULD NOT TRIGGER
contract Safe_DeprecatedSetupRole {
    mapping(bytes32 => mapping(address => bool)) private _roles;

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
    }

    function giveRole(bytes32 role, address account) external {
        _grantRole(role, account);
    }
}

// =============================================================================
// ── GAS-001: CUSTOM ERRORS INSTEAD OF require() STRINGS ──────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-custom-errors
contract Vulnerable_CustomErrors {
    uint256 public value;

    // BAD: string require messages cost extra gas
    function setValue(uint256 v) external {
        require(v > 0, "Value must be positive");
        require(v < 1000, "Value too high");
        value = v;
    }
}

// SHOULD NOT TRIGGER
contract Safe_CustomErrors {
    uint256 public value;
    error ValueNotPositive();
    error ValueTooHigh();

    function setValue(uint256 v) external {
        if (v == 0) revert ValueNotPositive();
        if (v >= 1000) revert ValueTooHigh();
        value = v;
    }
}

// =============================================================================
// ── GAS-002: LONG REVERT STRING (> 32 bytes) ─────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-long-revert-string
contract Vulnerable_LongRevertString {
    uint256 public balance;

    // BAD: string longer than 32 bytes costs extra bytecode
    function withdraw(uint256 amount) external {
        require(balance >= amount, "Withdrawal amount exceeds available balance"); // 43 bytes
        balance -= amount;
    }
}

// SHOULD NOT TRIGGER
contract Safe_LongRevertString {
    uint256 public balance;

    // SAFE: string <= 32 bytes
    function withdraw(uint256 amount) external {
        require(balance >= amount, "Insufficient balance");
        balance -= amount;
    }
}

// =============================================================================
// ── GAS-003: POST-INCREMENT IN LOOP ──────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-post-increment
contract Vulnerable_PostIncrement {
    uint256 public total;

    function sumArray(uint256[] calldata arr) external {
        for (uint256 i = 0; i < arr.length; i++) { // i++ post-increment
            total += arr[i];
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_PostIncrement {
    uint256 public total;

    function sumArray(uint256[] calldata arr) external {
        uint256 len = arr.length;
        for (uint256 i; i < len; ) {
            total += arr[i];
            unchecked { ++i; } // pre-increment in unchecked
        }
    }
}

// =============================================================================
// ── GAS-004: ARRAY LENGTH NOT CACHED IN LOOP ─────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-cache-array-length
contract Vulnerable_CacheArrayLength {
    address[] public list;

    function process() external view returns (uint256 sum) {
        for (uint256 i = 0; i < list.length; i++) { // list.length read every iter
            sum += list[i].balance;
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_CacheArrayLength {
    address[] public list;

    function process() external view returns (uint256 sum) {
        uint256 len = list.length; // cached
        for (uint256 i; i < len; ++i) {
            sum += list[i].balance;
        }
    }
}

// =============================================================================
// ── GAS-005: STATE VAR SET ONLY IN CONSTRUCTOR — SHOULD BE IMMUTABLE ─────────
// =============================================================================

// SHOULD TRIGGER: GAS-immutable-constructor
contract Vulnerable_ImmutableConstructor {
    address public token;   // set once in constructor, never changed
    uint256 public decimals; // same

    constructor(address _token, uint256 _decimals) {
        token = _token;     // state write in constructor
        decimals = _decimals;
    }
}

// SHOULD NOT TRIGGER
contract Safe_ImmutableConstructor {
    address public immutable token;   // already immutable
    uint256 public immutable decimals;

    constructor(address _token, uint256 _decimals) {
        token = _token;
        decimals = _decimals;
    }
}

// =============================================================================
// ── GAS-006: _msgSender() OVERHEAD ───────────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-msg-sender
contract Vulnerable_MsgSenderGas {
    address public lastCaller;

    // BAD: _msgSender() adds function call overhead vs msg.sender
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    function doSomething() external {
        lastCaller = _msgSender(); // unnecessary internal call
    }
}

// SHOULD NOT TRIGGER
contract Safe_MsgSenderGas {
    address public lastCaller;

    function doSomething() external {
        lastCaller = msg.sender; // direct, no overhead
    }
}

// =============================================================================
// ── GAS-007: UNCHECKED LOOP INCREMENTS ───────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-unchecked-increments
contract Vulnerable_UncheckedIncrements {
    uint256 public sum;

    function add(uint256[] calldata values) external {
        for (uint256 i = 0; i < values.length; i++) { // NOT unchecked
            sum += values[i];
        }
    }
}

// SHOULD NOT TRIGGER
contract Safe_UncheckedIncrements {
    uint256 public sum;

    function add(uint256[] calldata values) external {
        uint256 len = values.length;
        for (uint256 i; i < len; ) {
            sum += values[i];
            unchecked { ++i; }
        }
    }
}

// =============================================================================
// ── GAS-008: REDUNDANT BOOLEAN COMPARISON ────────────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-bool-compare
contract Vulnerable_BoolCompare {
    bool public paused;

    function tryAction() external view {
        require(paused == false, "Paused"); // redundant == false
    }

    function isActive() external view returns (bool) {
        return paused == false; // redundant
    }
}

// SHOULD NOT TRIGGER
contract Safe_BoolCompare {
    bool public paused;

    function tryAction() external view {
        require(!paused, "Paused");
    }

    function isActive() external view returns (bool) {
        return !paused;
    }
}

// =============================================================================
// ── GAS-009: this.function() EXTERNAL SELF-CALL ───────────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-this-external
contract Vulnerable_ThisExternal {
    uint256 public counter;

    function increment() public {
        counter++;
    }

    // BAD: this.increment() creates CALL opcode instead of JUMP
    function incrementTwice() external {
        this.increment();
        this.increment();
    }
}

// SHOULD NOT TRIGGER
contract Safe_ThisExternal {
    uint256 public counter;

    function increment() public {
        counter++;
    }

    // SAFE: direct internal call
    function incrementTwice() external {
        increment();
        increment();
    }
}

// =============================================================================
// ── GAS-010: STATE VAR INITIALIZED TO DEFAULT VALUE ──────────────────────────
// =============================================================================

// SHOULD TRIGGER: GAS-initialize-default-value
contract Vulnerable_InitializeDefaultValue {
    uint256 public counter = 0;      // redundant = 0
    bool public active = false;      // redundant = false
    address public owner = address(0); // redundant = address(0)
}

// SHOULD NOT TRIGGER
contract Safe_InitializeDefaultValue {
    uint256 public counter;  // EVM zero-initializes
    bool public active;      // defaults to false
    address public owner;    // defaults to address(0)

    constructor() {
        owner = msg.sender; // non-default explicit set
    }
}
