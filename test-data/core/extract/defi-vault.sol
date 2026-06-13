// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ═══════════════════════════════════════════════════════════════════════
// Complex DeFi Vault - Comprehensive test for CLI extract & scan commands
// Contains: true bugs, false positives, deep inheritance, complex state
// ═══════════════════════════════════════════════════════════════════════

// ── Base contracts ──────────────────────────────────────────────────────

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

abstract contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = _msgSender();
    }

    modifier onlyOwner() {
        require(_msgSender() == _owner, "Not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Zero address");
        _owner = newOwner;
        emit OwnershipTransferred(_owner, newOwner);
    }
}

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

abstract contract Pausable is Ownable {
    bool private _paused;

    event Paused(address account);
    event Unpaused(address account);

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(_paused, "Pausable: not paused");
        _;
    }

    function pause() external onlyOwner {
        _paused = true;
        emit Paused(_msgSender());
    }

    function unpause() external onlyOwner {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    function paused() public view returns (bool) {
        return _paused;
    }
}

// ── Interfaces ──────────────────────────────────────────────────────────

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IVaultStrategy {
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external returns (uint256);
    function balanceOf() external view returns (uint256);
}

// ── Library ─────────────────────────────────────────────────────────────

library SafeTransfer {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "TransferFrom failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN CONTRACT: DeFi Vault with multiple vulnerability patterns
// ═══════════════════════════════════════════════════════════════════════

contract DeFiVault is Ownable, ReentrancyGuard, Pausable {
    using SafeTransfer for IERC20;

    // ── State variables ─────────────────────────────────────────────
    IERC20 public token;
    IVaultStrategy public strategy;
    
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastDepositTime;
    mapping(address => bool) public isWhitelisted;
    
    uint256 public totalDeposited;
    uint256 public withdrawalFee; // in basis points (100 = 1%)
    uint256 public minDeposit;
    uint256 public cooldownPeriod;
    
    bool public emergencyMode;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount, uint256 fee);
    event StrategyUpdated(address indexed newStrategy);
    event EmergencyWithdraw(address indexed user, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
        withdrawalFee = 50; // 0.5%
        minDeposit = 1e18;
        cooldownPeriod = 1 hours;
    }

    // ════════════════════════════════════════════════════════════════
    // TRUE BUG #1: Reentrancy in withdraw (no nonReentrant modifier)
    // The external call happens BEFORE state update
    // ════════════════════════════════════════════════════════════════
    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(block.timestamp >= lastDepositTime[msg.sender] + cooldownPeriod, "Cooldown");
        
        uint256 fee = (amount * withdrawalFee) / 10000;
        uint256 netAmount = amount - fee;
        
        // BUG: External call BEFORE state update → reentrancy possible
        token.safeTransfer(msg.sender, netAmount);
        
        // State update AFTER external call
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
        
        emit Withdrawal(msg.sender, netAmount, fee);
    }

    // ════════════════════════════════════════════════════════════════
    // FALSE POSITIVE #1: Safe deposit — state update before external call
    // Should NOT trigger reentrancy since state is updated first
    // ════════════════════════════════════════════════════════════════
    function deposit(uint256 amount) external whenNotPaused {
        require(amount >= minDeposit, "Below minimum");
        
        // State update FIRST (safe pattern)
        balances[msg.sender] += amount;
        totalDeposited += amount;
        lastDepositTime[msg.sender] = block.timestamp;
        
        // External call AFTER state update (Checks-Effects-Interactions ✓)
        token.safeTransferFrom(msg.sender, address(this), amount);
        
        emit Deposit(msg.sender, amount);
    }

    // ════════════════════════════════════════════════════════════════
    // FALSE POSITIVE #2: Protected withdraw — has nonReentrant guard
    // Should NOT trigger reentrancy since it has the modifier
    // ════════════════════════════════════════════════════════════════
    function safeWithdraw(uint256 amount) external nonReentrant whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient");
        
        uint256 fee = (amount * withdrawalFee) / 10000;
        uint256 netAmount = amount - fee;
        
        // External call before state — but protected by nonReentrant
        token.safeTransfer(msg.sender, netAmount);
        
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
        
        emit Withdrawal(msg.sender, netAmount, fee);
    }

    // ════════════════════════════════════════════════════════════════
    // TRUE BUG #2: Arbitrary transferFrom — no auth check on 'from'
    // Should trigger: attacker can drain any approved user
    // ════════════════════════════════════════════════════════════════
    function depositFor(address from, address to, uint256 amount) external whenNotPaused {
        require(amount >= minDeposit, "Below minimum");
        
        // BUG: 'from' is user-controlled, no validation
        token.safeTransferFrom(from, address(this), amount);
        
        balances[to] += amount;
        totalDeposited += amount;
        lastDepositTime[to] = block.timestamp;
        
        emit Deposit(to, amount);
    }

    // ════════════════════════════════════════════════════════════════
    // FALSE POSITIVE #3: transferFrom with onlyOwner — should be safe
    // ════════════════════════════════════════════════════════════════
    function adminRescueTokens(address from, address to, uint256 amount) external onlyOwner {
        // Admin-only function — not exploitable
        token.safeTransferFrom(from, to, amount);
    }

    // ════════════════════════════════════════════════════════════════
    // TRUE BUG #3: ETH reentrancy — low-level call with state after
    // ════════════════════════════════════════════════════════════════
    function withdrawETH() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        
        // BUG: Send ETH before updating state
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "ETH transfer failed");
        
        balances[msg.sender] = 0;
    }

    // ════════════════════════════════════════════════════════════════
    // FALSE POSITIVE #4: ETH withdrawal protected by nonReentrant
    // ════════════════════════════════════════════════════════════════
    function safeWithdrawETH() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "ETH transfer failed");
        
        balances[msg.sender] = 0;
    }

    // ── Admin functions ─────────────────────────────────────────────
    
    function setStrategy(address _strategy) external onlyOwner {
        strategy = IVaultStrategy(_strategy);
        emit StrategyUpdated(_strategy);
    }

    function setWithdrawalFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "Max 10%");
        withdrawalFee = _fee;
    }

    function setMinDeposit(uint256 _min) external onlyOwner {
        minDeposit = _min;
    }

    function setCooldownPeriod(uint256 _period) external onlyOwner {
        cooldownPeriod = _period;
    }

    function setWhitelisted(address user, bool status) external onlyOwner {
        isWhitelisted[user] = status;
    }

    function setEmergencyMode(bool _mode) external onlyOwner {
        emergencyMode = _mode;
    }

    // ── Emergency ───────────────────────────────────────────────────

    function emergencyWithdraw() external {
        require(emergencyMode, "Not emergency");
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");
        
        balances[msg.sender] = 0;
        totalDeposited -= bal;
        
        token.safeTransfer(msg.sender, bal);
        emit EmergencyWithdraw(msg.sender, bal);
    }

    // ── View functions ──────────────────────────────────────────────
    
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    function getVaultBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function canWithdraw(address user) external view returns (bool) {
        return block.timestamp >= lastDepositTime[user] + cooldownPeriod;
    }

    receive() external payable {}
}

// ═══════════════════════════════════════════════════════════════════════
// SECONDARY CONTRACT: Token with additional test patterns
// ═══════════════════════════════════════════════════════════════════════

contract VaultToken is Ownable {
    string public name = "Vault Token";
    string public symbol = "VLT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // Standard ERC20 functions
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(_allowances[from][msg.sender] >= amount, "Allowance exceeded");
        require(_balances[from] >= amount, "Insufficient");
        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function allowance(address _owner, address spender) external view returns (uint256) {
        return _allowances[_owner][spender];
    }

    function mint(address to, uint256 amount) external onlyOwner {
        totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(uint256 amount) external {
        require(_balances[msg.sender] >= amount, "Insufficient");
        _balances[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }
}
