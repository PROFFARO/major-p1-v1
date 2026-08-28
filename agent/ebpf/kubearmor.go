// Package ebpf provides KubeArmor security policy parsing and posture enforcement logic.
package ebpf

import (
	"fmt"
	"strings"
	"sync"
)

// KubeArmorAction represents KubeArmor enforcement actions (Allow, Audit, Block).
type KubeArmorAction uint32

const (
	ActionKubeAllow KubeArmorAction = 0
	ActionKubeAudit KubeArmorAction = 1
	ActionKubeBlock KubeArmorAction = 2
)

// String returns a human-readable action string.
func (a KubeArmorAction) String() string {
	switch a {
	case ActionKubeAllow:
		return "ALLOW"
	case ActionKubeAudit:
		return "AUDIT"
	case ActionKubeBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

// KubeArmorPolicy represents a container security policy rule.
type KubeArmorPolicy struct {
	Name        string          `json:"name"`
	Namespace   string          `json:"namespace"`
	Action      KubeArmorAction `json:"action"`
	MatchPaths  []string        `json:"match_paths"`
	MatchDirs   []string        `json:"match_dirs"`
	MatchProcs  []string        `json:"match_procs"`
	Severity    string          `json:"severity"`
}

// KubeArmorEngine manages active security policies and evaluates telemetry events.
type KubeArmorEngine struct {
	mu       sync.RWMutex
	policies map[string]*KubeArmorPolicy
}

// NewKubeArmorEngine creates a new policy enforcement engine.
func NewKubeArmorEngine() *KubeArmorEngine {
	engine := &KubeArmorEngine{
		policies: make(map[string]*KubeArmorPolicy),
	}
	engine.initDefaultPolicies()
	return engine
}

func (e *KubeArmorEngine) initDefaultPolicies() {
	// Policy 1: Protect System Credentials
	e.AddPolicy(&KubeArmorPolicy{
		Name:        "k8s-block-credentials-access",
		Namespace:   "default",
		Action:      ActionKubeBlock,
		MatchPaths:  []string{"/etc/shadow", "/etc/sudoers"},
		Severity:    "Critical",
	})

	// Policy 2: Block Execution in /tmp
	e.AddPolicy(&KubeArmorPolicy{
		Name:       "k8s-block-tmp-execution",
		Namespace:  "default",
		Action:     ActionKubeBlock,
		MatchDirs:  []string{"/tmp/", "/var/tmp/", "/dev/shm/"},
		Severity:   "High",
	})
}

// AddPolicy registers a new KubeArmor security policy.
func (e *KubeArmorEngine) AddPolicy(policy *KubeArmorPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[policy.Name] = policy
}

// EvaluateEvent checks if a telemetry event matches any active KubeArmor policy.
func (e *KubeArmorEngine) EvaluateEvent(ev *Event) (KubeArmorAction, *KubeArmorPolicy) {
	if ev == nil {
		return ActionKubeAllow, nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		// Check path matches
		for _, path := range policy.MatchPaths {
			if strings.HasPrefix(ev.Filename, path) {
				return policy.Action, policy
			}
		}

		// Check directory matches
		for _, dir := range policy.MatchDirs {
			if strings.HasPrefix(ev.Filename, dir) && ev.Type == EventTypeExec {
				return policy.Action, policy
			}
		}

		// Check process matches
		for _, proc := range policy.MatchProcs {
			if ev.Comm == proc {
				return policy.Action, policy
			}
		}
	}

	return ActionKubeAllow, nil
}

// AuditLog formats a KubeArmor audit record string.
func (e *KubeArmorEngine) AuditLog(ev *Event, action KubeArmorAction, policy *KubeArmorPolicy) string {
	if policy == nil {
		return ""
	}
	return fmt.Sprintf("[KUBEARMOR %s] Policy='%s' PID=%d Comm='%s' File='%s' Severity=%s",
		action.String(), policy.Name, ev.PID, ev.Comm, ev.Filename, policy.Severity)
}
