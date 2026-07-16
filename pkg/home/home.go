// Package home manages the cross-platform ~/.w3goaudit directory: the user
// config file and the template home that mirrors the published template pack
// (nuclei-style — downloaded from GitHub Releases, never via git clone).
package home

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultTemplatesRepo is the GitHub repo whose latest release supplies the
// template pack.
const DefaultTemplatesRepo = "th13vn/w3goaudit-templates"

// Config is the user-global configuration (~/.w3goaudit/config.yml). Every key
// is overridable by a CLI flag; the file just changes the defaults.
type Config struct {
	Templates struct {
		Dir  string `yaml:"dir"`  // template home (default: <home>/templates)
		Repo string `yaml:"repo"` // releases source for --update-templates
	} `yaml:"templates"`
	Output struct {
		BaseDir string `yaml:"base_dir"` // "" = CWD; else write default-named folders here
		HTML    bool   `yaml:"html"`     // also emit HTML mirror by default
	} `yaml:"output"`
	Scan struct {
		MinSeverity   string   `yaml:"min_severity"`   // default --min-severity
		StrictImports bool     `yaml:"strict_imports"` // fail when any import is unresolved
		ExcludePaths  []string `yaml:"exclude_paths"`  // reserved: paths to skip
		Workers       int      `yaml:"workers"`        // reserved: 0 = auto
	} `yaml:"scan"`
	Report struct {
		RepoBase string `yaml:"repo_base"` // "" = relative paths; else source-link base
	} `yaml:"report"`
	Color string `yaml:"color"` // auto | never
}

// Dir returns the ~/.w3goaudit directory path.
func Dir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(h, ".w3goaudit"), nil
}

// ConfigPath returns the config.yml path.
func ConfigPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.yml"), nil
}

// DefaultTemplatesDir returns <home>/templates.
func DefaultTemplatesDir() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "templates"), nil
}

// defaultConfig returns a Config populated with the built-in defaults.
func defaultConfig() *Config {
	c := &Config{}
	c.Templates.Dir = "" // resolved to <home>/templates when empty
	c.Templates.Repo = DefaultTemplatesRepo
	c.Output.HTML = false
	c.Scan.ExcludePaths = []string{"node_modules", "lib", "out", "**/test/**", "**/mocks/**"}
	c.Scan.Workers = 0
	c.Color = "auto"
	return c
}

// Load reads config.yml, returning built-in defaults when the file is absent.
// Missing keys keep their default value.
func Load() (*Config, error) {
	cfg := defaultConfig()
	path, err := ConfigPath()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if cfg.Templates.Repo == "" {
		cfg.Templates.Repo = DefaultTemplatesRepo
	}
	return cfg, nil
}

// ResolveTemplatesDir returns the effective template home, honoring an explicit
// templates.dir from config and expanding a leading ~.
func (c *Config) ResolveTemplatesDir() (string, error) {
	if c.Templates.Dir != "" {
		return expandHome(c.Templates.Dir)
	}
	return DefaultTemplatesDir()
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		h, err := os.UserHomeDir()
		if err != nil {
			return p, err
		}
		if p == "~" {
			return h, nil
		}
		return filepath.Join(h, p[2:]), nil
	}
	return p, nil
}

// writeDefaultConfig writes a commented default config.yml.
func writeDefaultConfig(path string) error {
	const tmpl = `# w3goaudit configuration (~/.w3goaudit/config.yml)
# Every key here is a default; any CLI flag overrides it.
templates:
  dir: ""                          # template home ("" = ~/.w3goaudit/templates)
  repo: %s   # releases source for --update-templates
output:
  base_dir: ""                     # "" = current dir; else write result folders here
  html: false                      # also emit overview.html + findings.html
scan:
  min_severity: ""                 # default severity threshold (critical|high|medium|low|info)
  strict_imports: false            # fail instead of continuing when an import cannot be resolved
  exclude_paths:                   # reserved: paths skipped during discovery
    - node_modules
    - lib
    - out
    - "**/test/**"
    - "**/mocks/**"
  workers: 0                       # reserved: 0 = auto
report:
  repo_base: ""                    # "" = relative source links; else a repo base URL
color: auto                        # auto | never
`
	content := fmt.Sprintf(tmpl, DefaultTemplatesRepo)
	return os.WriteFile(path, []byte(content), 0644)
}

// EnsureInit performs first-run initialization: it creates ~/.w3goaudit, writes
// a default config.yml if absent, and — when the template home is empty —
// attempts to download the published pack. A download failure (offline, repo or
// release missing) is NOT fatal: the caller falls back to the embedded pack.
// logf receives human-readable progress/notice lines (may be nil).
func EnsureInit(logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	dir, err := Dir()
	if err != nil {
		logf("⚠ could not locate home directory: %v", err)
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		logf("⚠ could not create %s: %v", dir, err)
		return
	}

	cfgPath := filepath.Join(dir, "config.yml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := writeDefaultConfig(cfgPath); err != nil {
			logf("⚠ could not write default config: %v", err)
		} else {
			logf("Created default config: %s", cfgPath)
		}
	}

	cfg, err := Load()
	if err != nil {
		logf("⚠ could not load config (%v) — using built-in pack", err)
		return
	}
	tdir, err := cfg.ResolveTemplatesDir()
	if err != nil {
		return
	}
	if dirHasTemplates(tdir) {
		return // already populated
	}

	logf("First run: downloading templates from %s …", cfg.Templates.Repo)
	if tag, err := SyncTemplates(cfg.Templates.Repo, tdir); err != nil {
		logf("⚠ template download skipped (%v) — using built-in pack", err)
	} else {
		logf("Templates installed: %s (%s)", tag, tdir)
	}
}

// HasTemplates reports whether dir holds at least one .yaml/.yml template.
func HasTemplates(dir string) bool { return dirHasTemplates(dir) }

// dirHasTemplates reports whether dir exists and contains at least one .yaml/.yml.
func dirHasTemplates(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// LocalVersion reads <templatesDir>/.version (empty when absent).
func LocalVersion(templatesDir string) string {
	data, err := os.ReadFile(filepath.Join(templatesDir, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	ZipballURL string `json:"zipball_url"`
}

// latestRelease queries the GitHub Releases API for repo's latest release.
func latestRelease(repo string) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "w3goaudit")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s for %s", resp.Status, repo)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding release JSON: %w", err)
	}
	if rel.ZipballURL == "" {
		return nil, fmt.Errorf("release %q has no zipball", rel.TagName)
	}
	return &rel, nil
}

// SyncTemplates downloads the latest release zipball of repo and extracts its
// .yaml/.yml/.md files into templatesDir (replacing existing contents), then
// records the tag in .version. Returns the installed tag.
func SyncTemplates(repo, templatesDir string) (string, error) {
	rel, err := latestRelease(repo)
	if err != nil {
		return "", err
	}
	if err := downloadAndExtractVersion(rel.ZipballURL, templatesDir, rel.TagName); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// UpdateTemplates refreshes the template home when a newer release exists.
// Returns (installedTag, changed, error). When already current, changed=false.
func UpdateTemplates(repo, templatesDir string) (string, bool, error) {
	rel, err := latestRelease(repo)
	if err != nil {
		return "", false, err
	}
	local := LocalVersion(templatesDir)
	if local != "" && local == rel.TagName {
		return local, false, nil
	}
	if _, err := SyncTemplates(repo, templatesDir); err != nil {
		return "", false, err
	}
	return rel.TagName, true, nil
}

// Download / decompression size caps. Templates are small YAML/Markdown; these
// bound a hostile or corrupt zip so it cannot exhaust disk. NOTE: the download
// is authenticated by TLS only — GitHub's source zipball_url publishes no
// digest, so there is no checksum/signature verification. Templates are data
// (never executed), so a swapped pack cannot achieve code execution, but a
// MITM/compromised host could suppress detectors. Pin to a trusted mirror with
// a published checksum if that risk matters for your threat model.
const (
	maxZipDownloadBytes = 64 << 20  // 64 MiB compressed
	maxEntryBytes       = 8 << 20   // 8 MiB per extracted file
	maxArchiveBytes     = 128 << 20 // 128 MiB across accepted files
	maxArchiveFiles     = 4096      // accepted template/documentation files
	maxArchiveEntries   = 8192      // all central-directory entries, including ignored files
)

type archiveLimits struct {
	CompressedBytes int64
	EntryBytes      int64
	TotalBytes      int64
	Files           int
	Entries         int
}

var defaultArchiveLimits = archiveLimits{
	CompressedBytes: maxZipDownloadBytes,
	EntryBytes:      maxEntryBytes,
	TotalBytes:      maxArchiveBytes,
	Files:           maxArchiveFiles,
	Entries:         maxArchiveEntries,
}

// downloadAndExtractVersion installs one archive and, when version is non-empty,
// stages its .version marker as part of the same directory swap. GitHub source
// zipballs wrap everything in a single top-level directory, which is stripped.
// Only .yaml/.yml/.md files are written, keeping the template home clean. The
// extraction is staged in a sibling temp dir and installed with a rollback
// backup, so an extraction or install failure leaves the existing template
// home intact rather than half-replaced.
func downloadAndExtractVersion(zipURL, dest, version string) error {
	req, err := http.NewRequest(http.MethodGet, zipURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "w3goaudit")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading templates: %s", resp.Status)
	}

	tmp, err := os.CreateTemp("", "w3goaudit-templates-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// Cap the compressed download. Read one extra byte to detect overflow.
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, defaultArchiveLimits.CompressedBytes+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if n > defaultArchiveLimits.CompressedBytes {
		return fmt.Errorf("template zip exceeds %d bytes; refusing to extract", defaultArchiveLimits.CompressedBytes)
	}

	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return fmt.Errorf("opening template zip: %w", err)
	}
	defer zr.Close()

	// Stage into a sibling temp dir, then install with rollback. Extracting in
	// place after RemoveAll(dest) would leave dest partial on failure.
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dest), ".templates-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage) // no-op after a successful rename

	if err := extractArchive(&zr.Reader, stage, defaultArchiveLimits); err != nil {
		return err
	}
	if version != "" {
		if err := os.WriteFile(filepath.Join(stage, ".version"), []byte(version+"\n"), 0644); err != nil {
			return fmt.Errorf("staging .version: %w", err)
		}
	}
	if err := swapTemplateDirs(stage, dest, os.Rename, os.RemoveAll); err != nil {
		return err
	}
	return nil
}

type archiveEntry struct {
	file   *zip.File
	target string
}

// extractArchive preflights and extracts accepted template files while
// enforcing both declared and actually-streamed decompression limits.
func extractArchive(zr *zip.Reader, dest string, limits archiveLimits) error {
	if limits.EntryBytes <= 0 || limits.TotalBytes <= 0 || limits.Files <= 0 || limits.Entries <= 0 {
		return fmt.Errorf("invalid archive limits")
	}
	// zip.OpenReader has already parsed the central directory, but rejecting an
	// oversized entry table here bounds all subsequent allocation and work,
	// including directories and file types that extraction otherwise ignores.
	if len(zr.File) > limits.Entries {
		return fmt.Errorf("archive entry count exceeds %d", limits.Entries)
	}
	destRoot, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("resolving archive destination: %w", err)
	}

	entryCapacity := len(zr.File)
	if entryCapacity > limits.Files {
		entryCapacity = limits.Files
	}
	entries := make([]archiveEntry, 0, entryCapacity)
	portablePaths := make(map[string]string, entryCapacity)
	var declaredTotal uint64
	for _, f := range zr.File {
		rel, err := archiveRelativePath(f.Name)
		if err != nil {
			return fmt.Errorf("unsafe archive path %q: %w", f.Name, err)
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if rel == "" {
			continue
		}
		ext := strings.ToLower(path.Ext(rel))
		if ext != ".yaml" && ext != ".yml" && ext != ".md" {
			continue
		}
		if !f.Mode().IsRegular() {
			return fmt.Errorf("archive entry %s is not a regular file", rel)
		}
		// Windows paths are case-insensitive by default. Refuse aliases so the
		// same archive installs deterministically on every supported OS.
		portableKey := strings.ToLower(rel)
		if previous, ok := portablePaths[portableKey]; ok {
			return fmt.Errorf("archive paths %q and %q collide on case-insensitive filesystems", previous, rel)
		}
		portablePaths[portableKey] = rel
		if len(entries) >= limits.Files {
			return fmt.Errorf("archive template file count exceeds %d", limits.Files)
		}
		if f.UncompressedSize64 > uint64(limits.EntryBytes) {
			return fmt.Errorf("template file %s exceeds %d bytes; refusing to extract", rel, limits.EntryBytes)
		}
		if f.UncompressedSize64 > uint64(limits.TotalBytes) ||
			declaredTotal > uint64(limits.TotalBytes)-f.UncompressedSize64 {
			return fmt.Errorf("archive total decompressed size exceeds %d bytes", limits.TotalBytes)
		}
		declaredTotal += f.UncompressedSize64
		target, err := containedArchiveTarget(destRoot, rel)
		if err != nil {
			return fmt.Errorf("unsafe archive path %q: %w", f.Name, err)
		}
		entries = append(entries, archiveEntry{file: f, target: target})
	}
	if len(entries) == 0 {
		return fmt.Errorf("zip contained no template files")
	}

	var total int64
	for _, entry := range entries {
		n, err := extractOneLimited(entry.file, entry.target, limits.EntryBytes, limits.TotalBytes-total)
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

// swapTemplateDirs replaces dest without discarding it until stage has been
// successfully installed. rename and removeAll are injected for failure tests.
func swapTemplateDirs(stage, dest string, rename func(string, string) error, removeAll func(string) error) error {
	stage = filepath.Clean(stage)
	dest = filepath.Clean(dest)
	parent := filepath.Dir(dest)
	if filepath.Dir(stage) != parent {
		return fmt.Errorf("template stage and destination must have the same parent")
	}
	if stage == dest {
		return fmt.Errorf("template stage and destination must be different paths")
	}

	backup := filepath.Join(parent, "."+filepath.Base(dest)+"-backup-"+filepath.Base(stage))
	if err := removeAll(backup); err != nil {
		return fmt.Errorf("clearing stale template backup: %w", err)
	}

	hadDest := true
	if _, err := os.Lstat(dest); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("checking template dir: %w", err)
		}
		hadDest = false
	}
	if hadDest {
		if err := rename(dest, backup); err != nil {
			return fmt.Errorf("backing up template dir: %w", err)
		}
	}

	if err := rename(stage, dest); err != nil {
		if hadDest {
			if restoreErr := rename(backup, dest); restoreErr != nil {
				return fmt.Errorf("installing templates: %w; restoring previous templates: %v", err, restoreErr)
			}
		}
		return fmt.Errorf("installing templates: %w", err)
	}
	if hadDest {
		// The new directory is already committed at dest. Cleanup is best
		// effort: reporting an error here would make UpdateTemplates return
		// changed=false even though callers are already using the new pack.
		// The unique backup can be removed by a later maintenance pass.
		_ = removeAll(backup)
	}
	return nil
}

// archiveRelativePath validates a ZIP name using the strictest portable path
// rules supported by this package, then removes GitHub's top-level wrapper.
// Backslashes, drive/ADS colons, UNC/absolute forms, traversal, Windows device
// names, and components changed by Windows trailing-dot/space normalization are
// rejected even when extraction is running on Unix.
func archiveRelativePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("backslash path separator is not portable")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute or UNC path is not allowed")
	}

	parts := strings.Split(name, "/")
	for i, part := range parts {
		if part == "" {
			if i == len(parts)-1 {
				continue // conventional directory marker
			}
			return "", fmt.Errorf("empty path component is not allowed")
		}
		if err := validatePortablePathComponent(part); err != nil {
			return "", err
		}
	}
	if len(parts) < 2 {
		return "", nil
	}
	relParts := parts[1:]
	if len(relParts) == 1 && relParts[0] == "" {
		return "", nil
	}
	if relParts[len(relParts)-1] == "" {
		relParts = relParts[:len(relParts)-1]
	}
	return strings.Join(relParts, "/"), nil
}

func validatePortablePathComponent(component string) error {
	if component == "." || component == ".." {
		return fmt.Errorf("dot path component %q is not allowed", component)
	}
	if strings.TrimRight(component, " .") != component {
		return fmt.Errorf("path component %q has a trailing dot or space", component)
	}
	for _, r := range component {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return fmt.Errorf("path component %q contains a Windows-invalid character", component)
		}
	}

	base := component
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " ."))
	if isWindowsDeviceName(base) {
		return fmt.Errorf("path component %q is a reserved Windows device name", component)
	}
	return nil
}

func isWindowsDeviceName(name string) bool {
	switch name {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
		"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³":
		return true
	}
	if len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) {
		return name[3] >= '1' && name[3] <= '9'
	}
	return false
}

func containedArchiveTarget(destRoot, rel string) (string, error) {
	target := filepath.Join(destRoot, filepath.FromSlash(rel))
	within, err := filepath.Rel(destRoot, target)
	if err != nil {
		return "", fmt.Errorf("checking destination containment: %w", err)
	}
	if filepath.IsAbs(within) || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the archive destination")
	}
	return target, nil
}

func extractOneLimited(f *zip.File, target string, entryLimit, totalRemaining int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return 0, err
	}
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	out, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	removePartial := func() {
		_ = out.Close()
		_ = os.Remove(target)
	}

	readLimit := entryLimit
	if totalRemaining < readLimit {
		readLimit = totalRemaining
	}
	n, err := io.Copy(out, io.LimitReader(rc, readLimit+1))
	if err != nil {
		removePartial()
		return 0, err
	}
	if n > entryLimit {
		removePartial()
		return 0, fmt.Errorf("template file %s exceeds %d bytes; refusing to extract", target, entryLimit)
	}
	if n > totalRemaining {
		removePartial()
		return 0, fmt.Errorf("archive total decompressed size exceeds limit")
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(target)
		return 0, err
	}
	return n, nil
}
