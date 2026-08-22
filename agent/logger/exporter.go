// Package logger provides an asynchronous telemetry dataset exporter.
// It logs enriched kernel events to JSON Lines (.jsonl) files on disk
// for offline training of ML models (Isolation Forest, Random Forest).
package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

// Exporter manages dataset persistence to disk.
type Exporter struct {
	mu           sync.Mutex
	dir          string
	currentFile  *os.File
	writtenBytes int64
	maxFileBytes int64
	inCh         chan *agentebpf.Event
	done         chan struct{}
}

// NewExporter creates an exporter saving events into outputDir.
// Default max file size is 50MB before rotation.
func NewExporter(outputDir string, bufSize int) (*Exporter, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	exp := &Exporter{
		dir:          outputDir,
		maxFileBytes: 50 * 1024 * 1024, // 50 MB
		inCh:         make(chan *agentebpf.Event, bufSize),
		done:         make(chan struct{}),
	}

	if err := exp.rotate(); err != nil {
		return nil, err
	}

	return exp, nil
}

// Input returns the channel where events are queued for recording.
func (e *Exporter) Input() chan<- *agentebpf.Event {
	return e.inCh
}

// Start launches the background file writer worker.
func (e *Exporter) Start(ctx context.Context) {
	go func() {
		defer func() {
			e.mu.Lock()
			if e.currentFile != nil {
				e.currentFile.Sync()
				e.currentFile.Close()
			}
			e.mu.Unlock()
			close(e.done)
			log.Println("[exporter] Dataset exporter stopped.")
		}()

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		var batch []*agentebpf.Event

		for {
			select {
			case <-ctx.Done():
				// Drain remaining events in channel before exiting
				for len(e.inCh) > 0 {
					batch = append(batch, <-e.inCh)
				}
				e.flush(batch)
				return

			case ev, ok := <-e.inCh:
				if !ok {
					e.flush(batch)
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 100 {
					e.flush(batch)
					batch = batch[:0]
				}

			case <-ticker.C:
				if len(batch) > 0 {
					e.flush(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

// flush writes a batch of events to the current dataset file.
func (e *Exporter) flush(batch []*agentebpf.Event) {
	if len(batch) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, ev := range batch {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		data = append(data, '\n')

		n, err := e.currentFile.Write(data)
		if err != nil {
			log.Printf("[exporter] ERROR writing to dataset: %v", err)
			continue
		}
		e.writtenBytes += int64(n)

		if e.writtenBytes >= e.maxFileBytes {
			if err := e.rotate(); err != nil {
				log.Printf("[exporter] ERROR rotating dataset file: %v", err)
			}
		}
	}
}

// rotate closes the current file and opens a new timestamped .jsonl file.
func (e *Exporter) rotate() error {
	if e.currentFile != nil {
		e.currentFile.Sync()
		e.currentFile.Close()
	}

	filename := fmt.Sprintf("telemetry_%s.jsonl", time.Now().Format("20060102_150405"))
	fullPath := filepath.Join(e.dir, filename)

	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open dataset file: %w", err)
	}

	e.currentFile = f
	e.writtenBytes = 0
	log.Printf("[exporter] ✓ Logging telemetry dataset to %s", fullPath)
	return nil
}
