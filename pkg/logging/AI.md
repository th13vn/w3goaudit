# pkg/logging - Scan-Local Logging

## Purpose

Provides the immutable verbose-logging configuration shared by one scan. Each
scan constructs its own `*Logger` and injects it through reader, builder,
engine, database-load, and report options, preventing output and enabled-state
cross-talk between concurrent scans.

## API

- `New(enabled, writer)` creates a logger; a nil writer becomes `io.Discard`.
- `Disabled()` creates an explicitly silent logger.
- `(*Logger).Enabled()` reports the immutable enabled state.
- `(*Logger).Printf()` writes one newline-terminated message. Writes through a
  logger are mutex-serialized, so concurrent stages cannot interleave output.

## Compatibility Boundary

The historical package globals in `pkg/reader`, `pkg/builder`, `pkg/engine`,
`pkg/types`, and `pkg/report` remain as deprecated wrappers. Legacy constructors
continue to use those wrappers. New `WithOptions` constructors use only their
injected logger and do not read or mutate package-global logging state.

## Change Checklist

- Keep `Logger` configuration immutable after construction.
- Keep writes serialized and newline terminated.
- Pass one logger through nested scan objects instead of constructing new ones.
- Run `go test -race ./pkg/logging` after changes.
