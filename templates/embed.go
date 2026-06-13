// Package templates embeds the official WQL template pack into the binary so
// `w3goaudit <path>` works out of the box — without requiring the caller to have
// the repository's templates/ directory on disk (e.g. after `go install`).
package templates

import "embed"

// Official holds the built-in official security template pack. Files are
// accessible under the "official/" path prefix (see OfficialDir).
//
//go:embed all:official
var Official embed.FS

// OfficialDir is the path prefix of the embedded pack within Official.
const OfficialDir = "official"
