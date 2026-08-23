# pkg/aitriage – Remote candidate review

Implements `engine.AIReviewer` for an authenticated, isolated HTTP service.
The package owns transport only: WQL candidate generation and acceptance policy
remain in `pkg/engine`; container lifecycle and provider selection remain outside
the Go engine.

## Contract

- `NewHTTPReviewer(HTTPOptions{URL, APIKeyFile, Timeout})` validates an absolute
  HTTP(S) endpoint and reads a non-empty bearer credential from a file.
- `Review` POSTs one `engine.AIReviewRequest` as JSON and strictly decodes one
  `engine.AIReviewVerdict`.
- The default per-request timeout is 10 minutes because the downstream worker
  launches a bounded audit agent, not a low-latency classifier.
- Non-2xx response bodies are discarded and never surfaced in errors. They may
  contain private source or proxy diagnostics that echo secrets.
- Credentials are never serialized into report artifacts.

## Change checklist

- Keep failures fail-closed and free of response bodies or bearer values.
- Preserve `engine.AIReviewer`; do not make the generic engine depend on HTTP.
- Test transports without opening local sockets so restricted sandboxes pass.
