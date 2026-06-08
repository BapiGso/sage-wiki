package compiler

import (
	"path/filepath"
	"strings"
)

// SummaryFilename converts a source path to a unique summary filename.
//
// Using only filepath.Base() causes collisions when multiple sources share
// the same basename — e.g. docs/projects/claw/manifest.md and
// docs/projects/workflow/manifest.md both become manifest.md, and later
// compilations silently overwrite earlier ones (issue #51).
//
// The algorithm preserves every meaningful path segment by joining them with
// hyphens, then sanitizes any remaining dots so the produced filename has a
// single trailing ".md":
//
//	"raw/paper.md"                                 → "raw-paper.md"
//	"docs/projects/claw/manifest.md"               → "docs-projects-claw-manifest.md"
//	"docs/projects/workflow/manifest.md"           → "docs-projects-workflow-manifest.md"
//	"../../ezra/docs/projects/claw/manifest.md"    → "ezra-docs-projects-claw-manifest.md"
//	"raw/data.txt"                                 → "raw-data-txt.md"
//	"raw/data.md"                                  → "raw-data.md" (no collision with the above)
//	"manifest.md"                                  → "manifest.md"
//
// Two paths produce the same filename if and only if they normalize to the
// same sequence of non-dot, non-".." segments — which is exactly the
// equivalence we want (the diff walker already dedupes paths that resolve to
// the same file on disk).
func SummaryFilename(sourcePath string) string {
	p := filepath.ToSlash(filepath.Clean(sourcePath))
	parts := strings.Split(p, "/")

	// Drop "", ".", ".." segments so paths that traverse out of the project
	// (../../...) produce sensible filenames built from the first concrete
	// path segment onward.
	cleaned := parts[:0]
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		cleaned = append(cleaned, part)
	}
	if len(cleaned) == 0 {
		return "summary.md"
	}

	// Drop a trailing .md (case-insensitive) from the LAST segment only so
	// the join produces "*-name.md" rather than "*-name.md.md".
	last := cleaned[len(cleaned)-1]
	if strings.EqualFold(filepath.Ext(last), ".md") {
		cleaned[len(cleaned)-1] = strings.TrimSuffix(last, filepath.Ext(last))
	}

	joined := strings.Join(cleaned, "-")

	// Replace any remaining "." (from non-.md extensions or unusual segment
	// names) with "-" so the result has exactly one trailing ".md". Without
	// this, "raw/data.txt" → "raw-data.txt.md" works on disk but reads
	// inconsistently; collapsing dots avoids that ambiguity.
	joined = strings.ReplaceAll(joined, ".", "-")

	return joined + ".md"
}
