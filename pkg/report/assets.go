package report

import _ "embed"

// visNetworkJS is the vis-network graph library (v9.1.9), embedded so the HTML
// report is genuinely self-contained/offline. Previously the report loaded this
// from unpkg.com at view time, which made "standalone" reports phone home to a
// CDN and exposed them to a CDN-compromise supply-chain risk (the report embeds
// the reviewer's source). Inlining removes the network request entirely.
//
// Pinned to 9.1.9; refresh with:
//
//	curl -fsSL https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js \
//	  -o pkg/report/assets/vis-network.min.js
//
//go:embed assets/vis-network.min.js
var visNetworkJS string
