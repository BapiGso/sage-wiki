package compiler

import "testing"

func TestSummaryFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Basic single-segment paths
		{"manifest.md", "manifest.md"},
		{"paper.md", "paper.md"},

		// Two-segment paths
		{"raw/paper.md", "raw-paper.md"},
		{"raw/2026-04-10_benchmark.md", "raw-2026-04-10_benchmark.md"},
		{"docs/manifest.md", "docs-manifest.md"},

		// Deep paths — the collision case the PR fixes
		{"docs/projects/claw/manifest.md", "docs-projects-claw-manifest.md"},
		{"docs/projects/workflow/manifest.md", "docs-projects-workflow-manifest.md"},
		{"docs/projects/memory/manifest.md", "docs-projects-memory-manifest.md"},

		// Paths that traverse out of the project
		{"../../ezra/docs/projects/claw/manifest.md", "ezra-docs-projects-claw-manifest.md"},
		{"../../ezra/docs/manifest.md", "ezra-docs-manifest.md"},

		// Archive paths
		{"../../ezra/docs/projects/claw/archive/claw-v1-manifest.md", "ezra-docs-projects-claw-archive-claw-v1-manifest.md"},

		// Non-.md extensions: keep the extension as part of the name so
		// "raw/data.txt" doesn't collide with "raw/data.md"
		{"raw/data.txt", "raw-data-txt.md"},
		{"raw/data.md", "raw-data.md"},
		{"raw/image.png", "raw-image-png.md"},

		// Case-insensitive .md detection
		{"raw/README.MD", "raw-README.md"},
		{"raw/notes.Md", "raw-notes.md"},

		// Edge cases
		{"", "summary.md"},
		{".", "summary.md"},
		{"..", "summary.md"},
		{"./paper.md", "paper.md"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SummaryFilename(tt.input)
			if got != tt.want {
				t.Errorf("SummaryFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestSummaryFilename_NoCollisions asserts that a representative set of
// real-world source paths all produce distinct summary filenames. Pulled
// from the original PR's repro plus the adversarial cases I flagged in
// review (mid-path "docs/", cross-extension stems, root-vs-stripped).
func TestSummaryFilename_NoCollisions(t *testing.T) {
	paths := []string{
		// Same basename, different directories (the original PR's case)
		"../../ezra/docs/projects/claw/manifest.md",
		"../../ezra/docs/projects/workflow/manifest.md",
		"../../ezra/docs/projects/memory/manifest.md",
		"../../ezra/docs/manifest.md",
		"../../ezra/docs/projects/claw/archive/claw-v1-manifest.md",

		// Adversarial: "raw/docs/foo.md" must not collide with "raw/foo.md"
		"raw/docs/foo.md",
		"raw/foo.md",

		// Adversarial: same stem, different extension must not collide
		"raw/data.txt",
		"raw/data.md",

		// Adversarial: stripped-prefix shape must not collide with root file
		"docs/manifest.md",
		"manifest.md",
	}

	seen := make(map[string]string)
	for _, p := range paths {
		fn := SummaryFilename(p)
		if prev, ok := seen[fn]; ok {
			t.Errorf("collision: %q and %q both produce %q", prev, p, fn)
		}
		seen[fn] = p
	}
}
