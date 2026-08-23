package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

// AIReviewCounts summarizes candidate review outcomes.
type AIReviewCounts struct {
	Total    int `json:"total"`
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Error    int `json:"error"`
}

// AITriageJSON is the auditable record of every AI-reviewed candidate.
type AITriageJSON struct {
	SchemaVersion string                  `json:"schemaVersion"`
	Tool          ToolMeta                `json:"tool"`
	GeneratedAt   time.Time               `json:"generatedAt"`
	Counts        AIReviewCounts          `json:"counts"`
	Reviews       []engine.AIReviewRecord `json:"reviews"`
}

func BuildAITriageJSONAt(now time.Time, tool ToolMeta, reviews []engine.AIReviewRecord) *AITriageJSON {
	copyReviews := append([]engine.AIReviewRecord(nil), reviews...)
	if copyReviews == nil {
		copyReviews = []engine.AIReviewRecord{}
	}
	doc := &AITriageJSON{
		SchemaVersion: SchemaVersion, Tool: tool, GeneratedAt: now.UTC(),
		Reviews: copyReviews,
	}
	doc.Counts.Total = len(copyReviews)
	for _, review := range copyReviews {
		switch review.Status {
		case engine.AIReviewAccepted:
			doc.Counts.Accepted++
		case engine.AIReviewRejected:
			doc.Counts.Rejected++
		case engine.AIReviewError:
			doc.Counts.Error++
		}
	}
	return doc
}
