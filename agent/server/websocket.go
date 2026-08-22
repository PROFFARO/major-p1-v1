// Package server provides a combined REST API + WebSocket server
// for the eBPF telemetry agent. It exposes:
//
//   - GET  /ws              — WebSocket: live event stream
//   - GET  /api/status      — Agent health and stats
//   - GET  /api/blocklist   — List active PID & IP blocks
//   - POST /api/block/pid   — Block a PID  (body: {"pid":1234,"desc":"..."})
//   - POST /api/block/ip    — Block an IP  (body: {"ip":"1.2.3.4","desc":"..."})
//   - DELETE /api/block/pid — Unblock a PID (body: {"pid":1234})
//   - DELETE /api/block/ip  — Unblock an IP (body: {"ip":"1.2.3.4"})
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
	"github.com/proffaro/ebpf-ml-agent/mapmgr"
	"github.com/proffaro/ebpf-ml-agent/metrics"

	"github.com/gorilla/websocket"
)

// Server is the HTTP + WebSocket server for the agent.
type Server struct {
	events    <-chan *agentebpf.Event
	blocklist *mapmgr.BlocklistManager
	metrics   *metrics.Collector
	startTime time.Time

	// WebSocket client management
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool

	upgrader websocket.Upgrader
}

// NewServer creates a new server instance.
func NewServer(events <-chan *agentebpf.Event, bm *mapmgr.BlocklistManager, mc *metrics.Collector) *Server {
	return &Server{
		events:    events,
		blocklist: bm,
		metrics:   mc,
		startTime: time.Now(),
		clients:   make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			// Allow all origins (for local dashboard development)
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Start begins the HTTP server and the event broadcaster.
// It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.HandleFunc("/ws", s.handleWebSocket)

	// REST API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/blocklist", s.handleListBlocklist)
	mux.HandleFunc("/api/block/pid", s.handleBlockPID)
	mux.HandleFunc("/api/block/ip", s.handleBlockIP)

	// CORS middleware wrapper
	handler := corsMiddleware(mux)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Start broadcasting events to all connected WebSocket clients
	go s.broadcastLoop(ctx)

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		log.Println("[server] Shutting down HTTP server ...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("[server] ✓ HTTP + WebSocket server listening on %s", addr)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ─────────────────────────────────────────────────────────────
// WebSocket: Live Telemetry Stream
// ─────────────────────────────────────────────────────────────

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] WebSocket upgrade failed: %v", err)
		return
	}

	s.mu.Lock()
	s.clients[conn] = true
	clientCount := len(s.clients)
	s.mu.Unlock()

	log.Printf("[server] WebSocket client connected (total: %d)", clientCount)

	// Keep connection alive; read loop to detect disconnects
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.clients, conn)
			s.mu.Unlock()
			conn.Close()
			log.Printf("[server] WebSocket client disconnected")
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// broadcastLoop reads events from the channel and sends them to
// all connected WebSocket clients as JSON.
func (s *Server) broadcastLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.events:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}

			s.mu.RLock()
			for conn := range s.clients {
				err := conn.WriteMessage(websocket.TextMessage, data)
				if err != nil {
					conn.Close()
					// Removal from map happens in the read goroutine
				}
			}
			s.mu.RUnlock()
		}
	}
}

// ─────────────────────────────────────────────────────────────
// REST API Handlers
// ─────────────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.blocklist.GetStats()
	resp := map[string]interface{}{
		"status":         "running",
		"uptime_seconds": time.Since(s.startTime).Seconds(),
		"ws_clients":     len(s.clients),
		"blocklist":      stats,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.metrics != nil {
		writeJSON(w, http.StatusOK, s.metrics.Snapshot())
	} else {
		writeJSON(w, http.StatusOK, map[string]string{"error": "metrics collector not initialized"})
	}
}

func (s *Server) handleListBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]interface{}{
		"pid_blocks": s.blocklist.ListPIDBlocks(),
		"ip_blocks":  s.blocklist.ListIPBlocks(),
		"stats":      s.blocklist.GetStats(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBlockPID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			PID  uint32 `json:"pid"`
			Desc string `json:"desc"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.PID == 0 {
			http.Error(w, "pid is required", http.StatusBadRequest)
			return
		}
		if err := s.blocklist.BlockPID(req.PID, req.Desc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "blocked",
			"pid":    fmt.Sprint(req.PID),
		})

	case http.MethodDelete:
		var req struct {
			PID uint32 `json:"pid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := s.blocklist.UnblockPID(req.PID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "unblocked",
			"pid":    fmt.Sprint(req.PID),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			IP   string `json:"ip"`
			Desc string `json:"desc"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.IP == "" {
			http.Error(w, "ip is required", http.StatusBadRequest)
			return
		}
		if err := s.blocklist.BlockIP(req.IP, req.Desc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "blocked",
			"ip":     req.IP,
		})

	case http.MethodDelete:
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := s.blocklist.UnblockIP(req.IP); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "unblocked",
			"ip":     req.IP,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

