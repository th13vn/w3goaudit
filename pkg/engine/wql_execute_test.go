package engine

import "testing"

const delegatecallExecutionWQL = `
meta:
  id: CRITICAL-DELEGATECALL-USER-INPUT
  title: Delegatecall to User-Controlled Address
  severity: CRITICAL
  confidence: HIGH
  description: Delegatecall target comes from a function parameter.
  recommendation: Never delegatecall to user-supplied addresses.

query:
  from: entry_function
  select: delegatecall
  where:
    - not: {preset: access_controlled}
    - has:
        block: identifier
        receiver: true
        tainted: parameter
`

const delegatecallExecutionFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable_DelegatecallUserInput {
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}

contract Safe_OwnerGatedDelegatecall {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}
`

func TestWQLDelegatecallExecutesEndToEnd(t *testing.T) {
	tmpl, err := ParseTemplate(delegatecallExecutionWQL)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, delegatecallExecutionFixture).GetDatabase()
	findings := New(db).Execute(tmpl)

	matched := make(map[string]bool, len(findings))
	for _, finding := range findings {
		matched[finding.Location.Contract+"."+finding.Location.Function] = true
	}
	if !matched["Vulnerable_DelegatecallUserInput.execute"] {
		t.Fatalf("vulnerable delegatecall was not found; findings = %+v", findings)
	}
	if matched["Safe_OwnerGatedDelegatecall.execute"] {
		t.Fatalf("access-controlled delegatecall must not be found; findings = %+v", findings)
	}
}
