package sagewiki

import "testing"

func TestSearchRejectsEmptyQuery(t *testing.T) {
	if _, err := Search(t.TempDir(), SearchOptions{}); err == nil {
		t.Fatal("Search() error = nil, want empty-query error")
	}
}
