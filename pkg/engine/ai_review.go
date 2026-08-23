package engine

import (
	"context"
	"fmt"
)

// AIReviewer validates a broad WQL candidate against explicit security conditions.
type AIReviewer interface {
	Review(context.Context, AIReviewRequest) (AIReviewVerdict, error)
}

type AIReviewRequest struct {
	TemplateID        string           `json:"templateId"`
	Policy            AITemplatePolicy `json:"policy"`
	Finding           Finding          `json:"finding"`
	MatchedSource     string           `json:"matchedSource"`
	EnclosingFunction string           `json:"enclosingFunction,omitempty"`
	EnclosingContract string           `json:"enclosingContract,omitempty"`
}

type AIReviewVerdict struct {
	ValidBug             bool     `json:"valid_bug"`
	TriggerConditionsMet bool     `json:"trigger_conditions_met"`
	Confidence           float64  `json:"confidence"`
	Reasoning            string   `json:"reasoning"`
	MissingConditions    []string `json:"missing_conditions,omitempty"`
	Evidence             []string `json:"evidence,omitempty"`
}

type AIReviewStatus string

const (
	AIReviewAccepted AIReviewStatus = "accepted"
	AIReviewRejected AIReviewStatus = "rejected"
	AIReviewError    AIReviewStatus = "error"
)

type AIReviewRecord struct {
	TemplateID string           `json:"templateId"`
	Location   Location         `json:"location"`
	Status     AIReviewStatus   `json:"status"`
	Verdict    *AIReviewVerdict `json:"verdict,omitempty"`
	Error      string           `json:"error,omitempty"`
}

func (e *Engine) AIReviewRecords() []AIReviewRecord {
	if e == nil {
		return nil
	}
	return append([]AIReviewRecord(nil), e.aiReviewRecords...)
}

func (e *Engine) reviewAICandidates(tmpl *Template, candidates []*Finding) []*Finding {
	if tmpl == nil || tmpl.AI == nil || !tmpl.AI.Enabled {
		return candidates
	}
	accepted := make([]*Finding, 0, len(candidates))
	for _, finding := range candidates {
		record := AIReviewRecord{TemplateID: tmpl.Meta.ID}
		if finding != nil {
			record.Location = finding.Location
		}
		if e.aiReviewer == nil {
			record.Status, record.Error = AIReviewError, "AI reviewer is not configured"
			e.aiReviewRecords = append(e.aiReviewRecords, record)
			continue
		}
		verdict, err := e.aiReviewer.Review(context.Background(), e.aiReviewRequest(tmpl, finding))
		if err != nil {
			record.Status, record.Error = AIReviewError, err.Error()
			e.aiReviewRecords = append(e.aiReviewRecords, record)
			continue
		}
		record.Verdict = &verdict
		if verdict.ValidBug && verdict.TriggerConditionsMet && verdict.Confidence >= tmpl.AI.MinConfidence {
			record.Status = AIReviewAccepted
			if finding != nil {
				finding.AITriage = &verdict
				accepted = append(accepted, finding)
			}
		} else {
			record.Status = AIReviewRejected
		}
		e.aiReviewRecords = append(e.aiReviewRecords, record)
	}
	return accepted
}

func (e *Engine) aiReviewRequest(tmpl *Template, finding *Finding) AIReviewRequest {
	request := AIReviewRequest{TemplateID: tmpl.Meta.ID, Policy: *cloneAITemplatePolicy(tmpl.AI)}
	if finding == nil {
		return request
	}
	request.Finding = *finding
	start, end := finding.Location.Line, finding.Location.EndLine
	if finding.PrimaryAST != nil {
		start, end = finding.PrimaryAST.Start, finding.PrimaryAST.End
	}
	if end < start {
		end = start
	}
	request.MatchedSource = e.sourceSnippet(finding.Location.File, start, end)
	if finding.Location.Function != "" {
		request.EnclosingFunction = fmt.Sprintf("%s.%s", finding.Location.Contract, finding.Location.Function)
	}
	request.EnclosingContract = finding.Location.Contract
	return request
}
