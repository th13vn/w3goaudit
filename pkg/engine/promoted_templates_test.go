package engine

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// TestPromotedDetectorsDiscriminateVulnerableFromSafe runs each detector promoted
// from the benchmark lane into the shipped `official/` pack against its own
// fixture, and asserts the exact set of flagged sites.
//
// Both halves matter. The `want` list proves the detector still fires after
// promotion (the benchmark lane exercised it against a different corpus), and the
// `Safe_*` naming convention lets the assertion double as a false-positive gate:
// a promoted detector that fires on a deliberate safe control fails here rather
// than quietly degrading the pack's precision.
func TestPromotedDetectorsDiscriminateVulnerableFromSafe(t *testing.T) {
	cases := []struct {
		template string
		fixture  string
		want     []string
	}{
		{
			template: "templates/official/high/readonly-reentrancy-curve.yaml",
			fixture:  "test-data/security/readonly-reentrancy.sol",
			want:     []string{"Vulnerable_CurveReadOnlyReentrancy.lpPrice"},
		},
		{
			// Only the Vault-specific getPoolTokens shape ships; the generic
			// `getRate` variant was dropped because that name identifies any rate
			// provider (see the template's meta).
			template: "templates/official/high/readonly-reentrancy-balancer.yaml",
			fixture:  "test-data/security/readonly-reentrancy.sol",
			want:     []string{"Vulnerable_BalancerReadOnlyReentrancy.poolValue"},
		},
		{
			template: "templates/official/high/no-slippage-check.yaml",
			fixture:  "test-data/security/amm-integration.sol",
			want: []string{
				"Vulnerable_NoSlippageCheck.swapEth",
				"Vulnerable_NoSlippageCheck.swapTokens",
			},
		},
		{
			template: "templates/official/high/uniswap-callback-unprotected.yaml",
			fixture:  "test-data/security/amm-integration.sol",
			want: []string{
				"Vulnerable_UniswapCallbackUnprotected.uniswapV2Call",
				"Vulnerable_UniswapCallbackUnprotected.uniswapV3SwapCallback",
			},
		},
		{
			template: "templates/official/high/uniswap-v4-hook-unprotected.yaml",
			fixture:  "test-data/security/amm-integration.sol",
			want: []string{
				"Vulnerable_UniswapV4HookUnprotected.afterAddLiquidity",
				"Vulnerable_UniswapV4HookUnprotected.beforeSwap",
			},
		},
		{
			template: "templates/official/high/oracle-price-update-unrestricted.yaml",
			fixture:  "test-data/security/oracle-pricing.sol",
			want: []string{
				"Vulnerable_OraclePriceUpdateUnrestricted.setAssetPrice",
				"Vulnerable_OraclePriceUpdateUnrestricted.updateOracleTimestamp",
			},
		},
		{
			template: "templates/official/high/erc20-public-burn.yaml",
			fixture:  "test-data/security/token-callback-reentrancy.sol",
			want:     []string{"Vulnerable_ERC20PublicBurn.burn"},
		},
		{
			template: "templates/official/high/erc721-callback-reentrancy.yaml",
			fixture:  "test-data/security/token-callback-reentrancy.sol",
			want:     []string{"Vulnerable_ERC721CallbackReentrancy.mint"},
		},
		{
			template: "templates/official/high/erc777-callback-reentrancy.yaml",
			fixture:  "test-data/security/token-callback-reentrancy.sol",
			want:     []string{"Vulnerable_ERC777CallbackReentrancy.deposit"},
		},
		{
			template: "templates/official/medium/stale-oracle-data.yaml",
			fixture:  "test-data/security/oracle-pricing.sol",
			want:     []string{"Vulnerable_StaleOracleData.price"},
		},
		{
			template: "templates/official/medium/deprecated-chainlink-latestanswer.yaml",
			fixture:  "test-data/security/oracle-pricing.sol",
			want:     []string{"Vulnerable_DeprecatedChainlinkLatestAnswer.price"},
		},
		{
			template: "templates/official/medium/oracle-lp-spot-price.yaml",
			fixture:  "test-data/security/oracle-pricing.sol",
			want:     []string{"Vulnerable_OracleLpSpotPrice.getLpPrice"},
		},
		{
			template: "templates/official/medium/oracle-curve-spot-price.yaml",
			fixture:  "test-data/security/oracle-pricing.sol",
			want:     []string{"Vulnerable_OracleCurveSpotPrice.price"},
		},
	}

	root := repoRoot(t)
	for _, testCase := range cases {
		t.Run(filepath.Base(testCase.template), func(t *testing.T) {
			sources, err := reader.New().Read(filepath.Join(root, testCase.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			db, err := builder.New().Build(sources)
			if err != nil {
				t.Fatalf("build db: %v", err)
			}
			tmpl, err := LoadTemplate(filepath.Join(root, testCase.template))
			if err != nil {
				t.Fatalf("load template: %v", err)
			}

			var got []string
			for _, finding := range New(db).Execute(tmpl) {
				got = append(got, finding.Location.Contract+"."+finding.Location.Function)
			}
			sort.Strings(got)

			if strings.Join(got, ",") != strings.Join(testCase.want, ",") {
				t.Errorf("findings mismatch\n got: %v\nwant: %v", got, testCase.want)
			}
			for _, site := range got {
				if strings.HasPrefix(site, "Safe_") {
					t.Errorf("promoted detector fired on a safe control: %s", site)
				}
			}
		})
	}
}

// TestBidiCharacterDetectorFlagsOnlyTheBidiFixture covers the one promoted
// detector with `scope: source`, which reports per matching occurrence and per
// file rather than per declaration, so it cannot use the contract/function
// assertion above.
func TestBidiCharacterDetectorFlagsOnlyTheBidiFixture(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/security"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/bidi-characters.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("no findings: the bidi fixture's control characters were lost — do not normalize that file")
	}
	for _, finding := range findings {
		if filepath.Base(finding.Location.File) != "bidi-characters.sol" {
			t.Errorf("bidi detector fired on %s; only the bidi fixture should contain control characters",
				finding.Location.File)
		}
	}
}
