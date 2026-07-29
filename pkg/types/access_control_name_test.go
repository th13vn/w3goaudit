package types

import "testing"

// TestAccessControlNameVocabulary pins both halves of the authority-name
// vocabulary that gates the storage/mapping access-control paths.
//
// This name check is load-bearing: without it every mapping read on the caller
// would prove authorization, so `require(balances[msg.sender] > 0)` — which anyone
// can satisfy — would read as a privilege gate. The vocabulary must therefore stay
// a closed set of authority nouns. It is asserted here rather than only end-to-end
// so a future edit to the regex fails with a precise message.
func TestAccessControlNameVocabulary(t *testing.T) {
	// Conventional names for a privileged principal. Matching is substring-based
	// and case-insensitive, so plural and is/has prefixes are covered too.
	authority := []string{
		"owner", "_owner", "pendingOwner",
		"admin", "admins", "isAdmin",
		"governance", "governor", "gov", "councilMember", "steward",
		"authorized", "authorised", "auth", "permissions", "roles", "accessList",
		"allowlist", "allowed", "whitelist", "safelist",
		"operator", "operators", "manager", "managers", "controller", "controllers",
		"guardian", "keeper", "keepers", "moderators", "maintainers",
		"strategist", "executors", "relayers", "sequencer",
		"minter", "burners", "pauser", "upgrader", "distributor",
		"isTrusted", "trustedCallers", "signers", "validators", "attestors", "oracles",
	}
	for _, name := range authority {
		if !isAccessControlName(name) {
			t.Errorf("isAccessControlName(%q) = false; this is a conventional authority name", name)
		}
	}

	// Value-bearing and inverted names. A nonzero balance, stake, or nonce says
	// nothing about WHO may call, and a denylist check is inverted — treating any
	// of these as authorization would suppress genuine findings.
	notAuthority := []string{
		"balances", "balanceOf", "deposits", "stakes", "shares", "rewards",
		"totalSupply", "nonces", "lastUpdated", "reserves", "prices",
		"blacklist", "denylist", "blocked", "frozen",
		"", "x", "amount", "recipient", "tokenId",
	}
	for _, name := range notAuthority {
		if isAccessControlName(name) {
			t.Errorf("isAccessControlName(%q) = true; this is not proof of authorization", name)
		}
	}
}
