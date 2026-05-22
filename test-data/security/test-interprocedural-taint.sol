// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// ============================================================================
// VULNERABLE PATTERNS (Should be detected - 5 contracts)
// ============================================================================

// SHOULD TRIGGER: entrypoint forwards arbitrary user-controlled `from`.
contract VulnerableInternalForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        _internalDeposit(from, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD TRIGGER: local alias still carries the entrypoint parameter taint.
contract VulnerableAliasForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        address payer = from;
        _internalDeposit(payer, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD TRIGGER: arbitrary `from` survives multiple internal helper hops.
contract VulnerableNestedForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        _queueDeposit(from, amount);
    }

    function _queueDeposit(address payer, uint256 amount) internal {
        _recordDeposit(payer, amount);
    }

    function _recordDeposit(address source, uint256 amount) internal {
        _internalDeposit(source, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD TRIGGER: reassigned alias ends up pointing back to user-controlled `from`.
contract VulnerableAliasReassignmentForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        address payer = msg.sender;
        payer = from;
        _internalDeposit(payer, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD TRIGGER: struct field is still attacker-controlled through the request parameter.
contract VulnerableStructForward {
    struct DepositRequest {
        address from;
        uint256 amount;
    }

    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(DepositRequest calldata request) external {
        _internalDeposit(request.from, request.amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// ============================================================================
// SAFE PATTERNS (Should NOT be detected - 5 contracts)
// ============================================================================

// SHOULD NOT TRIGGER: helper receives msg.sender, not arbitrary user input.
contract SafeSenderForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        _internalDeposit(msg.sender, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD NOT TRIGGER: local alias points to msg.sender before forwarding.
contract SafeSenderAliasForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        address payer = msg.sender;
        _internalDeposit(payer, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD NOT TRIGGER: wrapper validates arbitrary-looking parameter before forwarding it.
contract SafeValidatedWrapper {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        require(from == msg.sender, "only self");
        _internalDeposit(from, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD NOT TRIGGER: alias is sanitized back to msg.sender before the helper call.
contract SafeAliasReassignmentForward {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function depositFrom(address from, uint256 amount) external {
        address payer = from;
        payer = msg.sender;
        _internalDeposit(payer, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}

// SHOULD NOT TRIGGER: role-gated wrapper may intentionally transfer from arbitrary accounts.
contract SafeRoleGuardedWrapper {
    IERC20 public token;
    address public admin;
    mapping(address => bool) public isOperator;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20(_token);
        admin = msg.sender;
    }

    modifier onlyOperator() {
        require(msg.sender == admin || isOperator[msg.sender], "not operator");
        _;
    }

    function operatorDeposit(address from, uint256 amount) external onlyOperator {
        _internalDeposit(from, amount);
    }

    function _internalDeposit(address from, uint256 amount) internal {
        token.transferFrom(from, address(this), amount);
        balances[from] += amount;
    }
}
