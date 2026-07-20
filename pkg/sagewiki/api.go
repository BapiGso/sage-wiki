// Package sagewiki provides a supported in-process API for embedding sage-wiki
// in other Go applications.
package sagewiki

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xoai/sage-wiki/internal/compiler"
	"github.com/xoai/sage-wiki/internal/config"
	"github.com/xoai/sage-wiki/internal/embed"
	"github.com/xoai/sage-wiki/internal/hybrid"
	"github.com/xoai/sage-wiki/internal/memory"
	"github.com/xoai/sage-wiki/internal/query"
	"github.com/xoai/sage-wiki/internal/storage"
	"github.com/xoai/sage-wiki/internal/vectors"
	"github.com/xoai/sage-wiki/internal/wiki"
)

// SearchOptions configures a hybrid BM25 and vector search.
type SearchOptions struct {
	Query     string
	Tags      []string
	BoostTags []string
	Limit     int
}

// SearchResult is one result returned by Search.
type SearchResult struct {
	ID          string   `json:"id"`
	Content     string   `json:"content"`
	Tags        []string `json:"tags,omitempty"`
	ArticlePath string   `json:"article_path,omitempty"`
	BM25Rank    int      `json:"bm25_rank,omitempty"`
	VectorRank  int      `json:"vector_rank,omitempty"`
	RRFScore    float64  `json:"rrf_score"`
}

// QueryResult is the answer and provenance returned by Query.
type QueryResult struct {
	Question   string   `json:"question"`
	Answer     string   `json:"answer"`
	Sources    []string `json:"sources,omitempty"`
	ChunksUsed []string `json:"chunks_used,omitempty"`
	Format     string   `json:"format"`
	OutputPath string   `json:"output_path,omitempty"`
}

// CompileOptions configures one compiler run.
type CompileOptions struct {
	DryRun  bool
	Fresh   bool
	Batch   bool
	NoCache bool
	Prune   bool
}

// CompileResult summarizes a compiler run without exposing internal types.
type CompileResult struct {
	Added             int `json:"added"`
	Modified          int `json:"modified"`
	Removed           int `json:"removed"`
	Summarized        int `json:"summarized"`
	ConceptsExtracted int `json:"concepts_extracted"`
	ArticlesWritten   int `json:"articles_written"`
	Errors            int `json:"errors"`
	EmbedErrors       int `json:"embed_errors"`
	TierIndexed       int `json:"tier_indexed"`
	TierEmbedded      int `json:"tier_embedded"`
	TierCompiled      int `json:"tier_compiled"`
}

// IngestResult describes a source added to the wiki project.
type IngestResult struct {
	SourcePath string `json:"source_path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
}

// StatusInfo contains the stable, serializable project status fields.
type StatusInfo struct {
	Project          string         `json:"project"`
	Mode             string         `json:"mode"`
	SourceCount      int            `json:"source_count"`
	PendingCount     int            `json:"pending_count"`
	ConceptCount     int            `json:"concept_count"`
	EntryCount       int            `json:"entry_count"`
	VectorCount      int            `json:"vector_count"`
	VectorDims       int            `json:"vector_dims"`
	EntityCount      int            `json:"entity_count"`
	RelationCount    int            `json:"relation_count"`
	LearningCount    int            `json:"learning_count"`
	EmbedProvider    string         `json:"embed_provider"`
	EmbedDims        int            `json:"embed_dims"`
	DimMismatch      bool           `json:"dim_mismatch"`
	GitClean         bool           `json:"git_clean"`
	LastCommit       string         `json:"last_commit"`
	LastMessage      string         `json:"last_message"`
	TierDistribution map[int]int    `json:"tier_distribution,omitempty"`
	FullyCompiled    int            `json:"fully_compiled,omitempty"`
	WithErrors       int            `json:"with_errors,omitempty"`
	AvgQuality       float64        `json:"avg_quality,omitempty"`
	SourceTypes      map[string]int `json:"source_types,omitempty"`
}

// InitGreenfield initializes a new standalone wiki project.
func InitGreenfield(projectDir, project, model string) error {
	return wiki.InitGreenfield(projectDir, project, model)
}

// InitVaultOverlay initializes sage-wiki over an existing document vault.
func InitVaultOverlay(projectDir, project string, sourceFolders, ignoreFolders []string, output, model string) error {
	return wiki.InitVaultOverlay(projectDir, project, sourceFolders, ignoreFolders, output, model)
}

// Search runs the same document-level hybrid search used by the CLI. If query
// embedding fails, it safely falls back to BM25-only search.
func Search(projectDir string, opts SearchOptions) ([]SearchResult, error) {
	if strings.TrimSpace(opts.Query) == "" {
		return nil, fmt.Errorf("search query is empty")
	}
	if opts.Limit <= 0 {
		opts.Limit = 10
	}

	db, err := storage.Open(filepath.Join(projectDir, ".sage", "wiki.db"))
	if err != nil {
		return nil, fmt.Errorf("search: open db: %w", err)
	}
	defer db.Close()

	memStore := memory.NewStore(db)
	vecStore := vectors.NewStore(db)
	searcher := hybrid.NewSearcher(memStore, vecStore)

	cfg, err := config.Load(filepath.Join(projectDir, "config.yaml"))
	if err != nil {
		return nil, fmt.Errorf("search: load config: %w", err)
	}

	var queryVec []float32
	if embedder := embed.NewFromConfig(cfg); embedder != nil {
		queryVec, _ = embedder.Embed(opts.Query)
	}

	results, err := searcher.Search(hybrid.SearchOpts{
		Query:        opts.Query,
		Tags:         opts.Tags,
		BoostTags:    opts.BoostTags,
		Limit:        opts.Limit,
		BM25Weight:   cfg.Search.HybridWeightBM25,
		VectorWeight: cfg.Search.HybridWeightVector,
	}, queryVec)
	if err != nil {
		return nil, err
	}

	out := make([]SearchResult, 0, len(results))
	for _, result := range results {
		out = append(out, SearchResult{
			ID: result.ID, Content: result.Content, Tags: result.Tags,
			ArticlePath: result.ArticlePath, BM25Rank: result.BM25Rank,
			VectorRank: result.VectorRank, RRFScore: result.RRFScore,
		})
	}
	return out, nil
}

// Query searches the wiki, asks the configured sage-wiki model to synthesize
// an answer, and preserves sage-wiki's configured output filing behavior.
func Query(projectDir, question, format string, topK int) (*QueryResult, error) {
	result, err := query.Query(projectDir, question, format, topK)
	if err != nil {
		return nil, err
	}
	return &QueryResult{
		Question: result.Question, Answer: result.Answer, Sources: result.Sources,
		ChunksUsed: result.ChunksUsed, Format: result.Format, OutputPath: result.OutputPath,
	}, nil
}

// Ingest adds a local file or an HTTP(S) URL to the configured source folder.
func Ingest(projectDir, target string) (*IngestResult, error) {
	var result *wiki.IngestResult
	var err error
	if strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") {
		result, err = wiki.IngestURL(projectDir, target)
	} else {
		result, err = wiki.IngestPath(projectDir, target)
	}
	if err != nil {
		return nil, err
	}
	return &IngestResult{SourcePath: result.SourcePath, Type: result.Type, Size: result.Size}, nil
}

// Compile runs one sage-wiki compilation cycle in the caller's process.
func Compile(projectDir string, opts CompileOptions) (*CompileResult, error) {
	result, err := compiler.Compile(projectDir, compiler.CompileOpts{
		DryRun: opts.DryRun, Fresh: opts.Fresh, Batch: opts.Batch,
		NoCache: opts.NoCache, Prune: opts.Prune,
	})
	if err != nil {
		return nil, err
	}
	return &CompileResult{
		Added: result.Added, Modified: result.Modified, Removed: result.Removed,
		Summarized: result.Summarized, ConceptsExtracted: result.ConceptsExtracted,
		ArticlesWritten: result.ArticlesWritten, Errors: result.Errors,
		EmbedErrors: result.EmbedErrors, TierIndexed: result.TierIndexed,
		TierEmbedded: result.TierEmbedded, TierCompiled: result.TierCompiled,
	}, nil
}

// Status returns project health and index statistics.
func Status(projectDir string) (*StatusInfo, error) {
	status, err := wiki.GetStatus(projectDir, nil)
	if err != nil {
		return nil, err
	}
	return &StatusInfo{
		Project: status.Project, Mode: status.Mode, SourceCount: status.SourceCount,
		PendingCount: status.PendingCount, ConceptCount: status.ConceptCount,
		EntryCount: status.EntryCount, VectorCount: status.VectorCount,
		VectorDims: status.VectorDims, EntityCount: status.EntityCount,
		RelationCount: status.RelationCount, LearningCount: status.LearningCount,
		EmbedProvider: status.EmbedProvider, EmbedDims: status.EmbedDims,
		DimMismatch: status.DimMismatch, GitClean: status.GitClean,
		LastCommit: status.LastCommit, LastMessage: status.LastMessage,
		TierDistribution: status.TierDistribution, FullyCompiled: status.FullyCompiled,
		WithErrors: status.WithErrors, AvgQuality: status.AvgQuality,
		SourceTypes: status.SourceTypes,
	}, nil
}
