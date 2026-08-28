package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
	"github.com/proffaro/ebpf-ml-agent/metrics"
)

func TestServer_RESTStatusAndMetricsEndpoints(t *testing.T) {
	evCh := make(chan *agentebpf.Event, 10)
	mc := metrics.NewCollector(nil, nil)
	srv := NewServer(evCh, mc)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", srv.handleStatus)
	mux.HandleFunc("/api/metrics", srv.handleMetrics)

	// Test /api/status
	req := httptest.NewRequest("GET", "/api/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /api/status, got %d", rec.Code)
	}

	var statusResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("Failed to unmarshal /api/status response: %v", err)
	}

	if statusResp["status"] != "running" {
		t.Errorf("Expected status 'running', got %v", statusResp["status"])
	}

	// Test /api/metrics
	reqMetrics := httptest.NewRequest("GET", "/api/metrics", nil)
	recMetrics := httptest.NewRecorder()
	mux.ServeHTTP(recMetrics, reqMetrics)

	if recMetrics.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /api/metrics, got %d", recMetrics.Code)
	}

	var metricsResp map[string]interface{}
	if err := json.Unmarshal(recMetrics.Body.Bytes(), &metricsResp); err != nil {
		t.Fatalf("Failed to unmarshal /api/metrics response: %v", err)
	}

	if _, exists := metricsResp["total_events"]; !exists {
		t.Errorf("Expected total_events in metrics response")
	}
}
