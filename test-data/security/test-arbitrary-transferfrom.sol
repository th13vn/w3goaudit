// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ArbitraryTransferFromTests
 * @notice Comprehensive test cases for SEC-ERC20-001: Arbitrary transferFrom vulnerability
 * @dev Tests functions that call transferFrom() with user-controlled parameters
 */

// Mock ERC20 interface
interface IERC20 {
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);
}

// ============================================================================
// VULNERABLE PATTERNS (Should be detected - 5 contracts)
// ============================================================================

/**
 * @notice VULNERABLE #1: Basic deposit with arbitrary from
 */
contract VulnerableDeposit {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULNERABLE: User can call deposit(victim, amount) to steal victim's tokens
    function deposit(address from, uint256 amount) external {
        token.transferFrom(from, address(this), amount);
        balances[msg.sender] += amount;
    }
}

/**
 * @notice VULNERABLE #2: Batch deposit with array of from addresses
 */
contract VulnerableBatchDeposit {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULNERABLE: Drain multiple accounts in one transaction
    function batchDeposit(
        address[] calldata from,
        uint256[] calldata amounts
    ) external {
        for (uint i = 0; i < from.length; i++) {
            token.transferFrom(from[i], address(this), amounts[i]);
            balances[msg.sender] += amounts[i];
        }
    }
}

/**
 * @notice VULNERABLE #3: Staking with user-controlled from
 */
contract VulnerableStaking {
    mapping(address => mapping(address => uint256)) public stakes;

    // VULNERABLE: Stake anyone's tokens
    function stake(address token, address from, uint256 amount) external {
        IERC20(token).transferFrom(from, address(this), amount);
        stakes[msg.sender][token] += amount;
    }
}

/**
 * @notice VULNERABLE #4: Swap/DEX with arbitrary source
 */
contract VulnerableSwap {
    IERC20 public tokenA;
    IERC20 public tokenB;

    constructor(address _tokenA, address _tokenB) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
    }

    // VULNERABLE: Swap from any account
    function swap(
        address fromAccount,
        uint256 amountA,
        uint256 amountB
    ) external {
        tokenA.transferFrom(fromAccount, address(this), amountA);
        tokenB.transferFrom(address(this), msg.sender, amountB);
    }
}

/**
 * @notice VULNERABLE #5: No explicit auth check
 */
contract VulnerableNoAuth {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // VULNERABLE: Missing authentication entirely
    function withdrawFrom(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }
}

// ============================================================================
// SAFE PATTERNS (Should NOT be detected - 8 contracts)
// ============================================================================

/**
 * @notice SAFE #1: Uses msg.sender as from
 */
contract SafeDeposit1 {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // SAFE: Only transfers from msg.sender
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}

/**
 * @notice SAFE #2: Has require(from == msg.sender) validation
 */
contract SafeDeposit2 {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // SAFE: Validates from parameter
    function depositFrom(address from, uint256 amount) external {
        require(from == msg.sender, "Can only deposit your own tokens");
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

/**
 * @notice SAFE #3: Has onlyOwner modifier
 */
contract SafeAdminDeposit {
    IERC20 public token;
    address public owner;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // SAFE: Admin-only function
    function adminDeposit(address from, uint256 amount) external onlyOwner {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

/**
 * @notice SAFE #4: Batch with validation in loop
 */
contract SafeBatchDeposit {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // SAFE: Validates each from address in loop
    function batchDeposit(
        address[] calldata from,
        uint256[] calldata amounts
    ) external {
        for (uint i = 0; i < from.length; i++) {
            require(from[i] == msg.sender, "Invalid from address");
            token.transferFrom(from[i], address(this), amounts[i]);
            balances[msg.sender] += amounts[i];
        }
    }
}

/**
 * @notice SAFE #5: Has msg.sender check in if-revert pattern
 */
contract SafeDepositWithIf {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // SAFE: Uses if-revert pattern for validation
    function depositFrom(address from, uint256 amount) external {
        if (from != msg.sender) {
            revert("Can only deposit your own tokens");
        }
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

/**
 * @notice SAFE #6: Standard ERC20 transferFrom implementation
 * @dev This is the INTENDED behavior - ERC20 transferFrom is SAFE
 */
contract StandardERC20 {
    string public name = "Test Token";
    string public symbol = "TEST";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    // SAFE: This is the standard ERC20 transferFrom - INTENDED behavior
    // The vulnerability is when OTHER functions call this with arbitrary params
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "Insufficient allowance");

        allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

/**
 * @notice SAFE #7: Has onlyRole modifier (complex access control)
 */
contract SafeRoleBasedDeposit {
    IERC20 public token;
    address public admin;
    mapping(address => bool) public isOperator;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
        admin = msg.sender;
    }

    modifier onlyRole(bool requirement) {
        require(requirement, "Access denied");
        _;
    }

    // SAFE: Protected by role-based access control
    function operatorDeposit(
        address from,
        uint256 amount
    ) external onlyRole(isOperator[msg.sender]) {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

/**
 * @notice SAFE #8: Has assert check
 */
contract SafeDepositWithAssert {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // SAFE: Uses assert for msg.sender check
    function depositFrom(address from, uint256 amount) external {
        assert(from == msg.sender);
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// ============================================================================
// EDGE CASES (Should NOT be detected - 2 contracts)
// ============================================================================

/**
 * @notice EDGE CASE #1: Internal function (not an entrypoint)
 */
contract EdgeCaseInternal {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    // Should NOT be detected - internal function, not entrypoint
    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }

    // Public wrapper that is safe
    function deposit(uint256 amount) external {
        _internalDeposit(msg.sender, amount);
    }
}

/**
 * @notice EDGE CASE #2: View function (cannot execute transferFrom)
 */
contract EdgeCaseView {
    // Should NOT be detected - view functions can't make state-changing calls
    function checkAllowance(
        address token,
        address from,
        address to
    ) external view returns (uint256) {
        return IERC20(token).allowance(from, to);
    }
}
