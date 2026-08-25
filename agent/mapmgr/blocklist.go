// Package mapmgr provides the dynamic feedback loop interface for
// managing eBPF hash map blocklists from user-space. The ML engine
// calls these APIs to block/unblock PIDs and IPs in real-time,
// which the kernel LSM and TC probes enforce immediately.
package mapmgr

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	cilium "github.com/cilium/ebpf"
	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

// BlocklistManager provides thread-safe operations to add, remove,
// and list entries in the kernel eBPF blocklist hash maps.
type BlocklistManager struct {
	mu             sync.RWMutex
	pidBlocklist   *cilium.Map // lsm_enforcer: pid_blocklist
	ipBlocklist    *cilium.Map // lsm_enforcer: ip_blocklist
	netIPBlocklist *cilium.Map // net_filter:   net_ip_blocklist (optional)

	// In-memory mirror for listing (BPF map iteration can be expensive)
	pidEntries map[uint32]*BlockEntry
	ipEntries  map[uint32]*BlockEntry
}

// BlockEntry is the user-facing representation of a blocklist entry.
type BlockEntry struct {
	Key         uint32    `json:"key"`
	KeyStr      string    `json:"key_str"`      // human-readable (PID number or IP address)
	RuleType    string    `json:"rule_type"`     // "pid" or "ip"
	Action      string    `json:"action"`        // "block" or "log"
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	HitCount    uint64    `json:"hit_count"`
}

// NewBlocklistManager creates a manager connected to the loaded BPF maps.
func NewBlocklistManager(pidMap, ipMap, netIPMap *cilium.Map) *BlocklistManager {
	return &BlocklistManager{
		pidBlocklist:   pidMap,
		ipBlocklist:    ipMap,
		netIPBlocklist: netIPMap,
		pidEntries:     make(map[uint32]*BlockEntry),
		ipEntries:      make(map[uint32]*BlockEntry),
	}
}

// ─────────────────────────────────────────────────────────────
// PID Blocklist Operations
// ─────────────────────────────────────────────────────────────

// BlockPID adds a PID to the kernel blocklist. The LSM enforcer will
// immediately begin returning -EPERM for that process.
func (bm *BlocklistManager) BlockPID(pid uint32, description string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	rule := makeBlockRule(agentebpf.ActionBlock, pid, 0, description)

	if err := bm.pidBlocklist.Update(pid, rule, cilium.UpdateAny); err != nil {
		return fmt.Errorf("failed to block PID %d: %w", pid, err)
	}

	bm.pidEntries[pid] = &BlockEntry{
		Key:         pid,
		KeyStr:      fmt.Sprintf("%d", pid),
		RuleType:    "pid",
		Action:      "block",
		Description: description,
		CreatedAt:   time.Now(),
	}

	log.Printf("[blocklist] ✓ Blocked PID %d: %s", pid, description)
	return nil
}

// UnblockPID removes a PID from the kernel blocklist.
func (bm *BlocklistManager) UnblockPID(pid uint32) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if err := bm.pidBlocklist.Delete(pid); err != nil && !errors.Is(err, cilium.ErrKeyNotExist) {
		return fmt.Errorf("failed to unblock PID %d: %w", pid, err)
	}

	delete(bm.pidEntries, pid)
	log.Printf("[blocklist] ✓ Unblocked PID %d", pid)
	return nil
}

// ─────────────────────────────────────────────────────────────
// IP Blocklist Operations
// ─────────────────────────────────────────────────────────────

// BlockIP adds an IPv4 address to both the LSM and TC blocklists.
// The LSM enforcer blocks socket_connect and the TC filter drops packets.
func (bm *BlocklistManager) BlockIP(ipStr string, description string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	ipKey, err := agentebpf.IPToU32(ipStr)
	if err != nil {
		return err
	}

	rule := makeBlockRule(agentebpf.ActionBlock, 0, ipKey, description)

	// Update LSM ip_blocklist
	if err := bm.ipBlocklist.Update(ipKey, rule, cilium.UpdateAny); err != nil {
		return fmt.Errorf("failed to block IP %s in LSM: %w", ipStr, err)
	}

	// Also update the TC net_ip_blocklist if available
	if bm.netIPBlocklist != nil {
		if err := bm.netIPBlocklist.Update(ipKey, rule, cilium.UpdateAny); err != nil {
			log.Printf("[blocklist] WARN: TC blocklist update failed for %s: %v", ipStr, err)
		}
	}

	bm.ipEntries[ipKey] = &BlockEntry{
		Key:         ipKey,
		KeyStr:      ipStr,
		RuleType:    "ip",
		Action:      "block",
		Description: description,
		CreatedAt:   time.Now(),
	}

	log.Printf("[blocklist] ✓ Blocked IP %s: %s", ipStr, description)
	return nil
}

// UnblockIP removes an IPv4 address from both blocklists.
func (bm *BlocklistManager) UnblockIP(ipStr string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	ipKey, err := agentebpf.IPToU32(ipStr)
	if err != nil {
		return err
	}

	if err := bm.ipBlocklist.Delete(ipKey); err != nil && !errors.Is(err, cilium.ErrKeyNotExist) {
		return fmt.Errorf("failed to unblock IP %s from LSM: %w", ipStr, err)
	}

	if bm.netIPBlocklist != nil {
		_ = bm.netIPBlocklist.Delete(ipKey) // best-effort
	}

	delete(bm.ipEntries, ipKey)
	log.Printf("[blocklist] ✓ Unblocked IP %s", ipStr)
	return nil
}

// ─────────────────────────────────────────────────────────────
// Query Operations (for REST API / Dashboard)
// ─────────────────────────────────────────────────────────────

// ListPIDBlocks returns all currently active PID block entries.
func (bm *BlocklistManager) ListPIDBlocks() []*BlockEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	entries := make([]*BlockEntry, 0, len(bm.pidEntries))
	for _, e := range bm.pidEntries {
		// Try to read hit_count from the BPF map
		bm.refreshHitCount(bm.pidBlocklist, e.Key, e)
		entries = append(entries, e)
	}
	return entries
}

// ListIPBlocks returns all currently active IP block entries.
func (bm *BlocklistManager) ListIPBlocks() []*BlockEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	entries := make([]*BlockEntry, 0, len(bm.ipEntries))
	for _, e := range bm.ipEntries {
		bm.refreshHitCount(bm.ipBlocklist, e.Key, e)
		entries = append(entries, e)
	}
	return entries
}

// Stats returns a summary of active block rules.
type Stats struct {
	ActivePIDBlocks int `json:"active_pid_blocks"`
	ActiveIPBlocks  int `json:"active_ip_blocks"`
}

// GetStats returns current blocklist statistics.
func (bm *BlocklistManager) GetStats() Stats {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return Stats{
		ActivePIDBlocks: len(bm.pidEntries),
		ActiveIPBlocks:  len(bm.ipEntries),
	}
}

// ─────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────

// rawBlockRule is the exact C struct block_rule_t binary layout for BPF map updates.
type rawBlockRule struct {
	RuleType    uint32
	TargetPID   uint32
	TargetIP    uint32
	Action      uint32
	CreationTS  uint64
	HitCount    uint64
	Description [64]byte
}

func init() {
	// Compile-time size check
	if sz := unsafe.Sizeof(rawBlockRule{}); sz != 96 {
		panic(fmt.Sprintf("rawBlockRule size mismatch: got %d, want 96", sz))
	}
}

// makeBlockRule creates a raw BPF-compatible block rule struct.
func makeBlockRule(action, pid, ip uint32, desc string) rawBlockRule {
	r := rawBlockRule{
		Action:     action,
		TargetPID:  pid,
		TargetIP:   ip,
		CreationTS: uint64(time.Now().UnixNano()),
	}

	if pid != 0 {
		r.RuleType = 1 // RULE_TYPE_PID
	} else {
		r.RuleType = 2 // RULE_TYPE_IP
	}

	// Copy description, null-terminated
	copy(r.Description[:], []byte(desc))
	return r
}

// refreshHitCount reads the current hit_count from the BPF map.
func (bm *BlocklistManager) refreshHitCount(m *cilium.Map, key uint32, entry *BlockEntry) {
	var raw rawBlockRule
	if err := m.Lookup(key, &raw); err == nil {
		entry.HitCount = raw.HitCount
	}
}
