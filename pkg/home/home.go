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
		MinSeverity  string   `yaml:"min_severity"`  // default --min-severity
		ExcludePaths []string `yaml:"exclude_paths"` // reserved: paths to skip
		Workers      int      `yaml:"workers"`       // reserved: 0 = auto
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

	cfg, _ := Load()
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
	if err := downloadAndExtract(rel.ZipballURL, templatesDir); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(templatesDir, ".version"), []byte(rel.TagName+"\n"), 0644); err != nil {
		return rel.TagName, fmt.Errorf("writing .version: %w", err)
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

// downloadAndExtract fetches a zip and extracts it into dest. GitHub source
// zipballs wrap everything in a single top-level directory, which is stripped.
// Only .yaml/.yml/.md files are written, keeping the template home clean.
func downloadAndExtract(zipURL, dest string) error {
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
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return fmt.Errorf("opening template zip: %w", err)
	}
	defer zr.Close()

	// Replace existing contents so removed templates don't linger.
	if err := os.RemoveAll(dest); err != nil {
		return fmt.Errorf("clearing template dir: %w", err)
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}

	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rel := stripTopLevel(f.Name)
		if rel == "" {
			continue
		}
		ext := strings.ToLower(filepath.Ext(rel))
		if ext != ".yaml" && ext != ".yml" && ext != ".md" {
			continue
		}
		if err := extractOne(f, filepath.Join(dest, rel)); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("zip contained no template files")
	}
	return nil
}

// stripTopLevel removes the leading "<repo>-<sha>/" component GitHub adds.
// It also defends against zip-slip by rejecting any "../" traversal.
func stripTopLevel(name string) string {
	name = filepath.ToSlash(name)
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	} else {
		return ""
	}
	if name == "" || strings.Contains(name, "..") {
		return ""
	}
	return name
}

func extractOne(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(target)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return err
	}
	return nil
}
