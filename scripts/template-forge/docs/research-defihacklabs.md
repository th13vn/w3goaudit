# Research — DeFiHackLabs

Captured 2026-06-24 from <https://github.com/SunWeb3Sec/DeFiHackLabs>.

## What it is

300+ real DeFi hack incidents reproduced as **Foundry PoCs**. Far richer than a blog: each
incident has runnable exploit code, on-chain references, and a fork block.

## Repo layout

- PoCs live under `src/test/YYYY-MM/<NAME>_exp.sol` (organized by incident month).
- Shared interfaces in `src/test/interface.sol`.
- Each PoC forks mainnet (or another chain) at a specific block and reproduces the exploit.

## PoC header schema (machine-parseable)

Verified against `src/test/2024-05/GFOX_exp.sol`:

```solidity
// @KeyInfo - Total Lost : 330K
// Attacker : https://etherscan.io/address/0xFcE19F8f823759b5867ef9a5055A376f20c5E454
// Attack Contract : https://etherscan.io/address/0x86C68d9e13d8d6a70b6423CEB2aEdB19b59F2AA5
// Vulnerable Contract : https://etherscan.io/address/0x47c4b3144de2c87a458d510c0c0911d1903d1686
// Attack Tx : https://etherscan.io/tx/0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc
// @Analysis
// Post-mortem : https://neptunemutual.com/blog/how-was-galaxy-fox-token-exploited/
// Twitter Guy : https://twitter.com/CertiKAlert/status/...
```

Body: fork block, e.g. `uint256 blocknumToForkFrom = 19_835_924;` →
`vm.createSelectFork("mainnet", blocknumToForkFrom);`

`src/sources/defihacklabs.ts#parsePoc` extracts: name, date (from path), loss text, attacker /
attack / vulnerable contract addresses, attack tx, reference links (blogs/tweets, excluding the
explorer fields), fork block, chain (from explorer host or fork network string).

## Enrichment (static-first)

`enrich/incident-enricher.ts` (best-effort, cached, never blocks the pipeline):

- **Etherscan v2** (`enrich/etherscan.ts`): verified source of the vulnerable contract
  (`getsourcecode`) + a compact attack-tx summary (`eth_getTransactionByHash`). Needs
  `ETHERSCAN_API_KEY`. Chain → chainid mapping for multichain incidents.
- **Blog** (`enrich/blogs.ts`): fetches the best reference (post-mortem/analysis), strips HTML
  to text. X/Twitter links are skipped (no useful static text).

## Optional PoC execution

`fetch:incidents --execute` (roadmap M3) would run the Foundry PoC against `FORK_RPC_URL` to
confirm reproduction before templating. Off by default — needs Foundry + an archive RPC.

## Listing + resume

`util/github.ts` (`HttpGitHubClient`) lists months + files via the GitHub contents API and
fetches raw bodies; both are disk-cached. `GITHUB_TOKEN` raises rate limits. The processed-path
set + last month are checkpointed in `fetch_cursor`, so a paused/interrupted pull resumes
cleanly.

## Sources

- <https://github.com/SunWeb3Sec/DeFiHackLabs>
- <https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-05/GFOX_exp.sol>
