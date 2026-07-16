package home

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractArchiveRejectsFileCount(t *testing.T) {
	limits := defaultArchiveLimits
	limits.Entries = limits.Files + 1
	zr := testZip(t, defaultArchiveLimits.Files+1, 1)
	err := extractArchive(zr, t.TempDir(), limits)
	if err == nil || !strings.Contains(err.Error(), "file count") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtractArchiveRejectsTotalEntryCountIncludingIgnored(t *testing.T) {
	limits := defaultArchiveLimits
	limits.Entries = 3
	zr := namedTestZip(t, map[string]string{
		"repo/ignored-1.txt": "x",
		"repo/ignored-2.txt": "x",
		"repo/ignored-3.txt": "x",
		"repo/template.yaml": "x",
	})
	err := extractArchive(zr, t.TempDir(), limits)
	if err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtractArchiveRejectsTotalSize(t *testing.T) {
	limits := defaultArchiveLimits
	limits.TotalBytes = 16
	zr := testZip(t, 3, 8)
	err := extractArchive(zr, t.TempDir(), limits)
	if err == nil || !strings.Contains(err.Error(), "total decompressed") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtractArchiveRemovesPartialFileOnEntryLimit(t *testing.T) {
	limits := defaultArchiveLimits
	limits.EntryBytes = 4
	dest := t.TempDir()
	zr := testZip(t, 1, 8)
	err := extractArchive(zr, dest, limits)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dest, "file-0000.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("partial file still exists: %v", statErr)
	}
}

func TestSwapRestoresDestinationOnInstallFailure(t *testing.T) {
	dest, stage := oldAndNewTemplateDirs(t)
	calls := 0
	rename := func(old, new string) error {
		calls++
		if calls == 2 {
			return errors.New("install rename failed")
		}
		return os.Rename(old, new)
	}
	err := swapTemplateDirs(stage, dest, rename, os.RemoveAll)
	if err == nil {
		t.Fatal("expected failure")
	}
	assertFileContains(t, filepath.Join(dest, "old.yaml"), "old")
	if _, statErr := os.Stat(filepath.Join(dest, "new.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("failed install leaked new template: %v", statErr)
	}
}

func TestSwapRejectsStageOutsideDestinationParent(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "home", "templates")
	stage := filepath.Join(root, "staging", "templates")
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	err := swapTemplateDirs(stage, dest, os.Rename, os.RemoveAll)
	if err == nil || !strings.Contains(err.Error(), "same parent") {
		t.Fatalf("err=%v", err)
	}
}

func TestSwapBackupCleanupFailureAfterCommitIsNonFatal(t *testing.T) {
	dest, stage := oldAndNewTemplateDirs(t)
	removeCalls := 0
	removeAll := func(path string) error {
		removeCalls++
		if removeCalls == 2 {
			return errors.New("backup cleanup failed")
		}
		return os.RemoveAll(path)
	}

	if err := swapTemplateDirs(stage, dest, os.Rename, removeAll); err != nil {
		t.Fatalf("committed install must remain successful: %v", err)
	}
	assertFileContains(t, filepath.Join(dest, "new.yaml"), "new")
	if _, err := os.Stat(filepath.Join(dest, "old.yaml")); !os.IsNotExist(err) {
		t.Fatalf("old template remains in committed destination: %v", err)
	}
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(dest), ".templates-backup-*"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("expected retained backup after cleanup failure, backups=%v err=%v", backups, err)
	}
	assertFileContains(t, filepath.Join(backups[0], "old.yaml"), "old")
}

func TestSwapStaleBackupCleanupFailureIsFatalBeforeMutation(t *testing.T) {
	dest, stage := oldAndNewTemplateDirs(t)
	err := swapTemplateDirs(stage, dest, os.Rename, func(string) error {
		return errors.New("stale backup cleanup failed")
	})
	if err == nil || !strings.Contains(err.Error(), "clearing stale") {
		t.Fatalf("err=%v", err)
	}
	assertFileContains(t, filepath.Join(dest, "old.yaml"), "old")
	assertFileContains(t, filepath.Join(stage, "new.yaml"), "new")
}

func TestArchiveRelativePathRejectsNonPortableNames(t *testing.T) {
	tests := []string{
		"/repo/file.yaml",
		`\\server\share\file.yaml`,
		"C:/repo/file.yaml",
		"repo/C:/file.yaml",
		`repo\file.yaml`,
		"repo/../outside.yaml",
		"repo/. /outside.yaml",
		"repo/dir./file.yaml",
		"repo/file.yaml ",
		"repo/file.yaml:stream",
		"repo//file.yaml",
		"repo/CON.yaml",
		"repo/aux/readme.md",
		"repo/NUL .yaml",
		"repo/com1.yaml",
		"repo/LPT9.md",
		"repo/COM¹.yaml",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if rel, err := archiveRelativePath(name); err == nil {
				t.Fatalf("archiveRelativePath(%q) = %q, want rejection", name, rel)
			}
		})
	}
}

func TestArchiveRelativePathAllowsSafeDottedName(t *testing.T) {
	got, err := archiveRelativePath("repo/a..b/template.v2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a..b/template.v2.yaml" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractArchiveRejectsCaseInsensitiveCollision(t *testing.T) {
	zr := namedTestZip(t, map[string]string{
		"repo/Finding.yaml": "first",
		"repo/finding.yaml": "second",
	})
	err := extractArchive(zr, t.TempDir(), defaultArchiveLimits)
	if err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("err=%v", err)
	}
}

func TestExtractArchiveRejectsNonRegularAcceptedEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	header := &zip.FileHeader{Name: "repo/link.yaml", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("../outside.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	err = extractArchive(zr, dest, defaultArchiveLimits)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dest, "link.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("non-regular entry was extracted: %v", statErr)
	}
}

func TestDownloadAndExtractVersionStagesMetadata(t *testing.T) {
	archive := testZipBytes(t, 1, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "templates")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "old.yaml"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, ".version"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadAndExtractVersion(server.URL, dest, "v2"); err != nil {
		t.Fatal(err)
	}
	assertFileContains(t, filepath.Join(dest, "file-0000.yaml"), "xxxxxxxx")
	assertFileContains(t, filepath.Join(dest, ".version"), "v2")
	if _, err := os.Stat(filepath.Join(dest, "old.yaml")); !os.IsNotExist(err) {
		t.Fatalf("old template still exists after successful swap: %v", err)
	}
}

func testZip(t *testing.T, files int, bytesPerFile int) *zip.Reader {
	t.Helper()
	data := testZipBytes(t, files, bytesPerFile)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func testZipBytes(t *testing.T, files int, bytesPerFile int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < files; i++ {
		w, err := zw.Create(fmt.Sprintf("repo/file-%04d.yaml", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("x"), bytesPerFile)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func namedTestZip(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func oldAndNewTemplateDirs(t *testing.T) (dest, stage string) {
	t.Helper()
	root := t.TempDir()
	dest, stage = filepath.Join(root, "templates"), filepath.Join(root, ".stage")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "old.yaml"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "new.yaml"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dest, stage
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), want) {
		t.Fatalf("path=%s content=%q err=%v", path, b, err)
	}
}
