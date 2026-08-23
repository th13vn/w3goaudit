// Package aitriage provides remote implementations of engine.AIReviewer.
package aitriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

const defaultTimeout = 10 * time.Minute

// HTTPOptions configures one authenticated AI-triage endpoint. The credential
// is read from a file so it never needs to appear in config, arguments, or
// process listings.
type HTTPOptions struct {
	URL        string
	APIKeyFile string
	Timeout    time.Duration
	HTTPClient *http.Client
}

// HTTPReviewer sends candidate-review requests to an isolated triage service.
type HTTPReviewer struct {
	url    string
	apiKey string
	client *http.Client
}

// NewHTTPReviewer validates configuration and reads the credential once.
func NewHTTPReviewer(opts HTTPOptions) (*HTTPReviewer, error) {
	endpoint := strings.TrimSpace(opts.URL)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("AI triage URL must be an absolute http(s) URL")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("AI triage URL must not contain credentials")
	}
	if strings.TrimSpace(opts.APIKeyFile) == "" {
		return nil, fmt.Errorf("AI triage API key file is required")
	}
	raw, err := os.ReadFile(opts.APIKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading AI triage API key file: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return nil, fmt.Errorf("AI triage API key file is empty")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("AI triage timeout must be positive")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	} else {
		cloned := *client
		cloned.Timeout = timeout
		client = &cloned
	}
	return &HTTPReviewer{url: endpoint, apiKey: key, client: client}, nil
}

// Review implements engine.AIReviewer. Non-success bodies are intentionally
// discarded because upstream proxies may echo credentials or private source.
func (r *HTTPReviewer) Review(ctx context.Context, request engine.AIReviewRequest) (engine.AIReviewVerdict, error) {
	var verdict engine.AIReviewVerdict
	payload, err := json.Marshal(request)
	if err != nil {
		return verdict, fmt.Errorf("encoding AI triage request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(payload))
	if err != nil {
		return verdict, fmt.Errorf("creating AI triage request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return verdict, fmt.Errorf("AI triage request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return verdict, fmt.Errorf("AI triage service returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&verdict); err != nil {
		return verdict, fmt.Errorf("decoding AI triage response: %w", err)
	}
	if verdict.Confidence < 0 || verdict.Confidence > 1 {
		return verdict, fmt.Errorf("decoding AI triage response: confidence must be between 0 and 1")
	}
	return verdict, nil
}
