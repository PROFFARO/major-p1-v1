// Package server provides a combined REST API + WebSocket server
// for the eBPF telemetry agent. It exposes:
//
//   - GET  /ws         — WebSocket: live event stream
//   - GET  /api/status  — Agent health and stats
//   - GET  /api/metrics — Agent Prometheus & probe metrics
package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
	"github.com/proffaro/ebpf-ml-agent/metrics"

	"github.com/gorilla/websocket"
)

type ClientConn struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (c *ClientConn) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteMessage(messageType, data)
}

// Server is the HTTP + WebSocket server for the agent.
type Server struct {
	events    <-chan *agentebpf.Event
	metrics   *metrics.Collector
	startTime time.Time

	// WebSocket client management
	mu      sync.RWMutex
	clients map[*ClientConn]bool

	upgrader websocket.Upgrader
}

// NewServer creates a new server instance.
func NewServer(events <-chan *agentebpf.Event, mc *metrics.Collector) *Server {
	return &Server{
		events:    events,
		metrics:   mc,
		startTime: time.Now(),
		clients:   make(map[*ClientConn]bool),
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

	// REST API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/metrics", s.handleMetrics)

	// WebSocket streaming endpoint
	mux.HandleFunc("/ws", s.handleWebSocket)

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
	rawConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] WebSocket upgrade failed: %v", err)
		return
	}

	client := &ClientConn{conn: rawConn}

	s.mu.Lock()
	s.clients[client] = true
	clientCount := len(s.clients)
	s.mu.Unlock()

	log.Printf("[server] WebSocket client connected (total: %d)", clientCount)

	// Keep connection alive & relay any client-injected synthetic events (e.g., attack simulation streams)
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.clients, client)
			s.mu.Unlock()
			client.conn.Close()
			log.Printf("[server] WebSocket client disconnected")
		}()
		for {
			msgType, msg, err := client.conn.ReadMessage()
			if err != nil {
				return
			}
			if msgType == websocket.TextMessage && len(msg) > 0 {
				s.mu.RLock()
				for target := range s.clients {
					if target != client {
						_ = target.WriteMessage(websocket.TextMessage, msg)
					}
				}
				s.mu.RUnlock()
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
			for client := range s.clients {
				err := client.WriteMessage(websocket.TextMessage, data)
				if err != nil {
					client.conn.Close()
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

	resp := map[string]interface{}{
		"status":         "running",
		"uptime_seconds": time.Since(s.startTime).Seconds(),
		"ws_clients":     len(s.clients),
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

