package reader

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GitInfo contains detected git repository information
type GitInfo struct {
	// RemoteURL is the web URL of the repository (e.g., https://github.com/user/repo)
	RemoteURL string
	// Branch is the current or default branch (e.g., main, master)
	Branch string
}

// DetectGitInfo detects git remote URL and branch from a project root
func DetectGitInfo(projectRoot string) *GitInfo {
	gitDir := filepath.Join(projectRoot, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return nil
	}

	info := &GitInfo{}

	// Read remote URL from .git/config
	configPath := filepath.Join(gitDir, "config")
	if remote := parseGitRemote(configPath); remote != "" {
		info.RemoteURL = GitRemoteToWebURL(remote)
	}

	// Try to detect current branch from .git/HEAD
	headPath := filepath.Join(gitDir, "HEAD")
	if branch := parseGitBranch(headPath); branch != "" {
		info.Branch = branch
	} else {
		info.Branch = "main" // Default to main
	}

	if info.RemoteURL == "" {
		return nil
	}

	return info
}

// parseGitRemote reads the remote origin URL from .git/config
func parseGitRemote(configPath string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRemoteOrigin := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[remote \"origin\"]" {
			inRemoteOrigin = true
			continue
		}

		if inRemoteOrigin {
			if strings.HasPrefix(line, "[") {
				// Entered another section
				break
			}
			// Accept both `url = X` and `url=X` (git accepts either spelling).
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "url" {
				return strings.TrimSpace(v)
			}
		}
	}
	_ = scanner.Err() // best-effort read; a truncated config just yields no URL

	return ""
}

// parseGitBranch reads the current branch from .git/HEAD
func parseGitBranch(headPath string) string {
	content, err := os.ReadFile(headPath)
	if err != nil {
		return ""
	}

	line := strings.TrimSpace(string(content))
	// Format: ref: refs/heads/main
	if rest, ok := strings.CutPrefix(line, "ref: refs/heads/"); ok {
		return rest
	}
	// Detached HEAD: .git/HEAD holds a raw 40-hex commit SHA. Return it so blob
	// links pin to that commit rather than falling back to a possibly-wrong
	// "main" branch.
	if isHexSHA(line) {
		return line
	}

	return ""
}

// isHexSHA reports whether s looks like a git object SHA (40 hex chars).
func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// GitRemoteToWebURL converts a git remote URL to a web URL
// Supports: SSH (git@github.com:user/repo.git) and HTTPS (https://github.com/user/repo.git)
func GitRemoteToWebURL(remote string) string {
	remote = strings.TrimSpace(remote)
	remote = strings.TrimSuffix(remote, ".git")

	// SSH format: git@github.com:user/repo
	if strings.HasPrefix(remote, "git@") {
		// git@github.com:user/repo -> https://github.com/user/repo
		remote = strings.TrimPrefix(remote, "git@")
		remote = strings.Replace(remote, ":", "/", 1)
		return "https://" + remote
	}

	// Already HTTPS format
	if strings.HasPrefix(remote, "https://") || strings.HasPrefix(remote, "http://") {
		return remote
	}

	return ""
}

// BuildGitFileURL creates a URL to view a file in the git web interface
func BuildGitFileURL(gitInfo *GitInfo, projectRoot, filePath string) string {
	if gitInfo == nil || gitInfo.RemoteURL == "" {
		return filePath // Return original path if no git info
	}

	// Get relative path from project root
	relPath, err := filepath.Rel(projectRoot, filePath)
	if err != nil {
		return filePath
	}

	// Normalize path separators for URL
	relPath = strings.ReplaceAll(relPath, "\\", "/")

	// Build URL based on host
	webURL := gitInfo.RemoteURL
	branch := gitInfo.Branch

	// GitHub, GitLab, Bitbucket all use /blob/<branch>/<path> format
	return webURL + "/blob/" + branch + "/" + relPath
}
