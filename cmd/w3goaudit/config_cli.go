package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/home"
)

// applyConfigDefaults applies config values to one immutable scan snapshot.
// CLI flags always win, and no Cobra-bound package global is mutated.
func applyConfigDefaults(cmd *cobra.Command, cfg *home.Config, opts *scanOptions) {
	if cfg == nil || opts == nil {
		return
	}
	if !cmd.Flags().Changed("html") && cfg.Output.HTML {
		opts.HTML = true
	}
	if !cmd.Flags().Changed("min-severity") && cfg.Scan.MinSeverity != "" {
		opts.MinSeverity = cfg.Scan.MinSeverity
	}
	if !cmd.Flags().Changed("strict-imports") {
		opts.StrictImports = cfg.Scan.StrictImports
	}
	if !cmd.Flags().Changed("no-color") && strings.EqualFold(cfg.Color, "never") {
		opts.NoColor = true
	}
	opts.OutputBaseDir = cfg.Output.BaseDir

	// Resolve the template home; only use it when it actually holds templates,
	// so loadScanTemplates can cleanly fall back to the embedded pack.
	if dir, err := cfg.ResolveTemplatesDir(); err == nil && home.HasTemplates(dir) {
		opts.TemplateHomeDir = dir
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
