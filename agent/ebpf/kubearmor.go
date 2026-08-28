// Package ebpf provides KubeArmor policy enforcement posture and container isolation management.
package ebpf

import (
	"fmt"
	"strings"
	"sync"
)

// KubeArmorAction enum (kubearmor_policy.h)
type KubeArmorAction uint32

const (
	KubeArmorActionAllow KubeArmorAction = 0
	KubeArmorActionAudit KubeArmorAction = 1
	KubeArmorActionBlock KubeArmorAction = 2
)

// KubeArmorPosture enum
type KubeArmorPosture uint32

const (
	KubeArmorPostureProcess KubeArmorPosture = 101
	KubeArmorPostureFile    KubeArmorPosture = 102
	KubeArmorPostureNetwork KubeArmorPosture = 103
	KubeArmorPostureCapable KubeArmorPosture = 104
)

// KubeArmorPolicyRule mirror of struct kubearmor_policy_rule
type KubeArmorPolicyRule struct {
	PostureType KubeArmorPosture `json:"posture_type"`
	Action      KubeArmorAction  `json:"action"`
	Path        string           `json:"path"`
	Source      string           `json:"source"`
}

// KubeArmorContainerPosture mirror of struct kubearmor_container_posture
type KubeArmorContainerPosture struct {
	PidNS       uint32          `json:"pid_ns"`
	MntNS       uint32          `json:"mnt_ns"`
	ProcPosture KubeArmorAction `json:"proc_posture"`
	FilePosture KubeArmorAction `json:"file_posture"`
	NetPosture  KubeArmorAction `json:"net_posture"`
}

// KubeArmorPolicyEngine manages container security policy evaluation and block enforcement.
type KubeArmorPolicyEngine struct {
	mu         sync.RWMutex
	postures   map[uint32]*KubeArmorContainerPosture
	rules      []*KubeArmorPolicyRule
	auditLogs  []string
}

// NewKubeArmorPolicyEngine creates a new KubeArmor security policy engine.
func NewKubeArmorPolicyEngine() *KubeArmorPolicyEngine {
	return &KubeArmorPolicyEngine{
		postures: make(map[uint32]*KubeArmorContainerPosture),
		rules:    make([]*KubeArmorPolicyRule, 0),
	}
}

// AddRule registers a security policy rule.
func (e *KubeArmorPolicyEngine) AddRule(rule *KubeArmorPolicyRule) {
	if rule == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// SetContainerPosture configures security posture enforcement for a given mount namespace.
func (e *KubeArmorPolicyEngine) SetContainerPosture(mntNS uint32, posture *KubeArmorContainerPosture) {
	if posture == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.postures[mntNS] = posture
}

// EvaluateAccess evaluates an access request against active KubeArmor security posture rules.
func (e *KubeArmorPolicyEngine) EvaluateAccess(mntNS uint32, postureType KubeArmorPosture, path string) KubeArmorAction {
	e.mu.RLock()
	defer e.mu.RUnlock()

	containerPosture, exists := e.postures[mntNS]
	if !exists {
		// Default behavior: AUDIT mode
		return KubeArmorActionAudit
	}

	var action KubeArmorAction
	switch postureType {
	case KubeArmorPostureProcess:
		action = containerPosture.ProcPosture
	case KubeArmorPostureFile:
		action = containerPosture.FilePosture
	case KubeArmorPostureNetwork:
		action = containerPosture.NetPosture
	default:
		action = KubeArmorActionAllow
	}

	// Specific rule matching takes precedence over container default posture
	for _, r := range e.rules {
		if r.PostureType == postureType && strings.HasPrefix(path, r.Path) {
			return r.Action
		}
	}

	return action
}

// RecordAuditLog appends an audit event entry.
func (e *KubeArmorPolicyEngine) RecordAuditLog(logEntry string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.auditLogs = append(e.auditLogs, fmt.Sprintf("[%s] %s", fmt.Sprint(uint64(0)), logEntry))
	if len(e.auditLogs) > 1000 {
		e.auditLogs = e.auditLogs[1:]
	}
}
