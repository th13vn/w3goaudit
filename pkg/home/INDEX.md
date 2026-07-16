# pkg/home — User config & template home (`~/.w3goaudit`)

Manages the cross-platform `~/.w3goaudit` directory: the user config file and
the template home, mirroring the published template pack nuclei-style (downloaded
from GitHub Releases — never `git clone`).

## Responsibilities

- Locate `~/.w3goaudit` via `os.UserHomeDir()` (same path semantics on macOS,
  Linux, Windows).
- Load/parse `config.yml` (`gopkg.in/yaml.v3`), falling back to built-in
  defaults when the file or individual keys are absent.
- First-run init: create the dir, write a commented default `config.yml`, and
  download the template pack. **Failures are non-fatal** — the caller falls back
  to the embedded official pack.
- Download + extract the latest release zipball into `templates/`, staging the
  release tag in `templates/.version` before installation. Defends against
  zip-slip and cross-platform path aliases: absolute/UNC/drive paths,
  backslashes, colons/ADS, traversal, Windows device names, trailing-dot/space
  normalization, and case-insensitive collisions are rejected before writing.
  The GitHub top-level wrapper directory is stripped.
- **Rollback-safe replace:** the zip is extracted into a sibling temp dir. The
  existing home is renamed to a sibling backup, the complete stage is renamed
  into place, and the backup is restored if installation fails. Once the new
  directory is committed, backup deletion is best-effort: cleanup failure does
  not falsely report an unsuccessful/no-change update.
- **Archive caps:** the compressed download is capped at 64 MiB, each extracted
  file at 8 MiB, accepted files at 4,096, all central-directory entries
  (including ignored files/directories) at 8,192, and total decompressed output
  at 128 MiB. Accepted `.yaml`/`.yml`/`.md` entries must also carry regular-file
  mode; ZIP symlinks and other special entries are rejected before extraction.
  Declared sizes are preflighted and actual streamed bytes are checked; a file
  that crosses a limit is removed instead of being left partial.
- **Integrity tradeoff (documented, not fixed):** the download is authenticated
  by TLS only — GitHub's source `zipball_url` publishes no digest, so there is no
  checksum/signature verification. Templates are data (never executed), so this
  is not RCE, but a swapped/MITM'd pack could suppress detectors. Pin a trusted
  mirror with a published checksum if that matters for your threat model.
- Update check (`--update-templates`): compare local `.version` to the latest
  release tag; refresh only when newer.

## Key types & functions (`home.go`)

| Symbol                                           | Role                                                            |
| ------------------------------------------------ | --------------------------------------------------------------- |
| `Config`                                         | User config struct; every key is a flag default.                |
| `Load()`                                         | Read `config.yml`, return defaults when missing.                |
| `Dir()`, `ConfigPath()`, `DefaultTemplatesDir()` | Path resolution.                                                |
| `(*Config).ResolveTemplatesDir()`                | Effective template home (honors `templates.dir`, expands `~`).  |
| `EnsureInit(logf)`                               | First-run provisioning (config + template download).            |
| `SyncTemplates(repo, dir)`                       | Download+extract latest release → `dir`, write `.version`.      |
| `UpdateTemplates(repo, dir)`                     | Refresh when a newer tag exists; returns `(tag, changed, err)`. |
| `LocalVersion(dir)`                              | Read `<dir>/.version`.                                          |
| `HasTemplates(dir)`                              | True when dir holds ≥1 `.yaml/.yml`.                            |
| `DefaultTemplatesRepo`                           | `th13vn/w3goaudit-templates`.                                   |

## Config schema (`config.yml`)

```yaml
templates: {dir, repo}
output:    {base_dir, html}
scan:      {min_severity, strict_imports, exclude_paths, workers}   # exclude_paths/workers reserved
report:    {repo_base}                              # reserved
color:     auto | never
```

## Consumers

- `cmd/w3goaudit/config_cli.go` — applies config defaults to one immutable scan
  option snapshot; an explicitly set CLI flag always wins. It also drives
  `-T/--update-templates`.
- `cmd/w3goaudit/root.go` — calls `home.Load` + `home.EnsureInit` at scan start
  and passes the resolved home directory into the scan option snapshot for
  template precedence (`--template` > home > embedded).

## Change checklist

- [ ] New config key → add to `Config`, `defaultConfig`, the `config.yml`
      template in `writeDefaultConfig`, and wire it in `config_cli.go`.
- [ ] Changed download/extract behavior → keep the zip-slip guard and the
      embedded-fallback contract (never hard-fail a scan on a download error).
- [ ] Update `docs/usage.md` (config + `--update-templates`) on any change.
