package aitriage

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestHTTPReviewerSendsBearerCredentialAndDecodesVerdict(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "triage.key")
	if err := os.WriteFile(keyPath, []byte("w3-test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer w3-test-key" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		return response(http.StatusOK, `{"valid_bug":true,"trigger_conditions_met":true,"confidence":0.93,"reasoning":"reachable loss","evidence":["C.sol:9"]}`), nil
	})}

	reviewer, err := NewHTTPReviewer(HTTPOptions{
		URL:        "http://triage.internal/review",
		APIKeyFile: keyPath,
		Timeout:    time.Second,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := reviewer.Review(context.Background(), engine.AIReviewRequest{TemplateID: "lossy-rounding"})
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.ValidBug || !verdict.TriggerConditionsMet || verdict.Confidence != 0.93 {
		t.Fatalf("verdict = %#v", verdict)
	}
}

func TestHTTPReviewerRejectsNonSuccessWithoutLeakingResponseOrKey(t *testing.T) {
	const secret = "w3-do-not-leak"
	keyPath := filepath.Join(t.TempDir(), "triage.key")
	if err := os.WriteFile(keyPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusBadGateway, "provider echoed "+secret), nil
	})}

	reviewer, err := NewHTTPReviewer(HTTPOptions{URL: "http://triage.internal/review", APIKeyFile: keyPath, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reviewer.Review(context.Background(), engine.AIReviewRequest{})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "provider echoed") {
		t.Fatalf("error leaked response material: %v", err)
	}
}

func TestHTTPReviewerRejectsMalformedJSON(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "triage.key")
	if err := os.WriteFile(keyPath, []byte("w3-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{`), nil
	})}

	reviewer, err := NewHTTPReviewer(HTTPOptions{URL: "http://triage.internal/review", APIKeyFile: keyPath, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Review(context.Background(), engine.AIReviewRequest{}); err == nil || !strings.Contains(err.Error(), "decoding AI triage response") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPReviewerEnforcesTimeout(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "triage.key")
	if err := os.WriteFile(keyPath, []byte("w3-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}

	reviewer, err := NewHTTPReviewer(HTTPOptions{URL: "http://triage.internal/review", APIKeyFile: keyPath, Timeout: 10 * time.Millisecond, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reviewer.Review(context.Background(), engine.AIReviewRequest{}); err == nil || !strings.Contains(err.Error(), "AI triage request") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPReviewerRequiresNonEmptyCredentialFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "triage.key")
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPReviewer(HTTPOptions{URL: "http://127.0.0.1", APIKeyFile: keyPath}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v", err)
	}
}
