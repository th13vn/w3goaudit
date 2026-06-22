package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/home"
)

// Config-derived state applied to the scan. These are seeded from
// ~/.w3goaudit/config.yml and overridden by explicit CLI flags.
var (
	outputBaseDir   string // config output.base_dir
	templateHomeDir string // resolved ~/.w3goaudit/templates when populated
	templatesRepo   string // config templates.repo (download source)
)

// applyConfigDefaults seeds flag globals from the user config for any flag the
// user did not explicitly set. CLI flags always win.
func applyConfigDefaults(cmd *cobra.Command, cfg *home.Config) {
	if cfg == nil {
		return
	}
	if !cmd.Flags().Changed("html") && cfg.Output.HTML {
		htmlOutput = true
	}
	if !cmd.Flags().Changed("min-severity") && cfg.Scan.MinSeverity != "" {
		minSeverity = cfg.Scan.MinSeverity
	}
	if !cmd.Flags().Changed("no-color") && strings.EqualFold(cfg.Color, "never") {
		noColor = true
	}
	outputBaseDir = cfg.Output.BaseDir
	templatesRepo = cfg.Templates.Repo

	// Resolve the template home; only use it when it actually holds templates,
	// so loadScanTemplates can cleanly fall back to the embedded pack.
	if dir, err := cfg.ResolveTemplatesDir(); err == nil && home.HasTemplates(dir) {
		templateHomeDir = dir
	}
}

// runUpdateTemplates implements --update-templates: refresh the template home
// from the configured releases repo. A missing repo/release is reported as a
// notice (exit 0), not an error, so the embedded pack keeps the tool working.
func runUpdateTemplates(cfg *home.Config) error {
	dir, err := cfg.ResolveTemplatesDir()
	if err != nil {
		return err
	}
	repo := cfg.Templates.Repo
	if repo == "" {
		repo = home.DefaultTemplatesRepo
	}

	fmt.Printf("Checking %s for template updates …\n", repo)
	tag, changed, err := home.UpdateTemplates(repo, dir)
	if err != nil {
		fmt.Printf("No published template release available yet (%v) — using the built-in pack.\n", err)
		return nil
	}
	if !changed {
		fmt.Printf("Templates already up to date (%s).\n", tag)
		return nil
	}
	fmt.Printf("Templates updated to %s: %s\n", tag, dir)
	return nil
}
