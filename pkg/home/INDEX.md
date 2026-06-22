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
- Download + extract the latest release zipball into `templates/`, recording the
  tag in `templates/.version`. Defends against zip-slip and strips the GitHub
  top-level wrapper directory.
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
scan:      {min_severity, exclude_paths, workers}   # exclude_paths/workers reserved
report:    {repo_base}                              # reserved
color:     auto | never
```

## Consumers

- `cmd/w3goaudit/config_cli.go` — `applyConfigDefaults` seeds flag globals;
  `runUpdateTemplates` drives `-T/--update-templates`.
- `cmd/w3goaudit/root.go` — calls `home.Load` + `home.EnsureInit` at scan start;
  `cmd/w3goaudit/scan_filters.go` reads the resolved home dir for the template
  precedence (`--template` > home > embedded).

## Change checklist

- [ ] New config key → add to `Config`, `defaultConfig`, the `config.yml`
      template in `writeDefaultConfig`, and wire it in `config_cli.go`.
- [ ] Changed download/extract behavior → keep the zip-slip guard and the
      embedded-fallback contract (never hard-fail a scan on a download error).
- [ ] Update `docs/usage.md` (config + `--update-templates`) on any change.
