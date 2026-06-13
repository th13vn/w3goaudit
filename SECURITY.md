# Security Policy

w3goaudit is a security tool, so we take the security of the tool itself
seriously.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately via one of:

- GitHub's **"Report a vulnerability"** (Security → Advisories) on this repo, or
- email the maintainer at the address listed on the GitHub profile.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal Solidity input / template / command line),
- the `w3goaudit version` output.

We aim to acknowledge reports within a few days and to ship a fix or mitigation
as soon as practical, crediting reporters who wish to be named.

## Scope

In-scope examples:

- Code execution or injection when **opening a generated report** (the HTML
  report embeds scanned source — see the escaping in `pkg/report`).
- A crafted contract or template that crashes the scanner (panic / OOM / hang)
  rather than failing gracefully.
- Path traversal or arbitrary file write via output/template paths.

Out of scope:

- False positives / false negatives in detectors (open a normal issue).
- Findings in the *contracts you scan* — those are the tool's output, not tool
  vulnerabilities.

## Supported versions

Until a 1.0 release, only the latest `main` is supported. Pin a tagged release
in CI and upgrade to receive fixes.
