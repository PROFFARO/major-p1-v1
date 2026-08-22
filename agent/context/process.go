// Package context provides real-time process metadata enrichment for telemetry events.
// It inspects /proc/<pid>/ to populate executable paths, command line arguments,
// parent process details, and binary SHA256 hashes with LRU caching.
package context

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

// ProcCacheEntry caches metadata for a process executable to prevent disk thrashing.
type ProcCacheEntry struct {
	ExePath    string
	Cmdline    string
	ParentComm string
	ExeHash    string
	Timestamp  time.Time
}

// ProcessResolver enriches telemetry events with /proc metadata.
type ProcessResolver struct {
	mu         sync.RWMutex
	cache      map[uint32]*ProcCacheEntry
	hashCache  map[string]string // ExePath -> SHA256
	maxCacheAge time.Duration
}

// NewProcessResolver initializes a process context resolver.
func NewProcessResolver() *ProcessResolver {
	pr := &ProcessResolver{
		cache:       make(map[uint32]*ProcCacheEntry),
		hashCache:   make(map[string]string),
		maxCacheAge: 10 * time.Second,
	}
	// Start periodic cache cleanup worker
	go pr.cleaner()
	return pr
}

// Enrich fills in ExePath, Cmdline, ParentComm, and ExeHash on an Event struct.
func (pr *ProcessResolver) Enrich(ev *agentebpf.Event) {
	if ev == nil || ev.PID == 0 {
		return
	}

	// 1. Check process cache
	pr.mu.RLock()
	entry, found := pr.cache[ev.PID]
	pr.mu.RUnlock()

	if !found || time.Since(entry.Timestamp) > pr.maxCacheAge {
		entry = pr.lookupProc(ev.PID, ev.PPID)
		pr.mu.Lock()
		pr.cache[ev.PID] = entry
		pr.mu.Unlock()
	}

	ev.ExePath = entry.ExePath
	ev.Cmdline = entry.Cmdline
	ev.ParentComm = entry.ParentComm
	ev.ExeHash = entry.ExeHash
}

// lookupProc reads /proc/<pid>/exe, /proc/<pid>/cmdline, and /proc/<ppid>/comm
func (pr *ProcessResolver) lookupProc(pid, ppid uint32) *ProcCacheEntry {
	entry := &ProcCacheEntry{
		Timestamp: time.Now(),
	}

	// Read /proc/<pid>/exe symlink
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		entry.ExePath = exePath
		entry.ExeHash = pr.hashFile(exePath)
	}

	// Read /proc/<pid>/cmdline
	cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil && len(cmdBytes) > 0 {
		// Replace null bytes with spaces
		args := strings.Split(string(cmdBytes), "\x00")
		entry.Cmdline = strings.TrimSpace(strings.Join(args, " "))
	}

	// Read parent comm from /proc/<ppid>/comm
	if ppid > 0 {
		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
		if err == nil {
			entry.ParentComm = strings.TrimSpace(string(commBytes))
		}
	}

	return entry
}

// hashFile computes or retrieves the cached SHA256 hash of an executable file.
func (pr *ProcessResolver) hashFile(path string) string {
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}

	pr.mu.RLock()
	hash, found := pr.hashCache[path]
	pr.mu.RUnlock()
	if found {
		return hash
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Limit hash calculation to first 10MB to avoid long pauses on large binaries
	h := sha256.New()
	if _, err := io.CopyN(h, f, 10*1024*1024); err != nil && err != io.EOF {
		return ""
	}

	hashStr := hex.EncodeToString(h.Sum(nil))

	pr.mu.Lock()
	pr.hashCache[path] = hashStr
	pr.mu.Unlock()

	return hashStr
}

// cleaner periodically removes stale cache entries.
func (pr *ProcessResolver) cleaner() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		pr.mu.Lock()
		now := time.Now()
		for pid, entry := range pr.cache {
			if now.Sub(entry.Timestamp) > pr.maxCacheAge {
				delete(pr.cache, pid)
			}
		}
		// Limit hash cache size
		if len(pr.hashCache) > 1000 {
			pr.hashCache = make(map[string]string)
		}
		pr.mu.Unlock()
	}
}

// GetProcessTree returns process details for a given PID.
func (pr *ProcessResolver) GetProcessTree(pid uint32) map[string]interface{} {
	tree := make(map[string]interface{})
	curr := pid
	chain := []map[string]string{}

	for depth := 0; depth < 5 && curr > 1; depth++ {
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", curr))
		commBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", curr))
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", curr))

		node := map[string]string{
			"pid":  strconv.Itoa(int(curr)),
			"exe":  exe,
			"comm": strings.TrimSpace(string(commBytes)),
		}
		chain = append(chain, node)

		if err != nil {
			break
		}

		// Parse parent PID (PPID) from /proc/<pid>/stat field #4
		fields := strings.Fields(string(statBytes))
		if len(fields) >= 4 {
			ppid, err := strconv.Atoi(fields[3])
			if err != nil || ppid <= 0 {
				break
			}
			curr = uint32(ppid)
		} else {
			break
		}
	}

	tree["process_chain"] = chain
	return tree
}
