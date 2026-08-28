// Package ebpf provides Cilium Tetragon LSM execution capability enforcer and Sigkill action handling.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

const (
	TetragonActionPost     uint32 = 0
	TetragonActionEnforce  uint32 = 1
	TetragonActionSigkill  uint32 = 9
)

// TetragonExecCred mirror of struct tetragon_exec_cred_t (tetragon_types.h)
type TetragonExecCred struct {
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	EUID           uint32 `json:"euid"`
	EGID           uint32 `json:"egid"`
	SUID           uint32 `json:"suid"`
	SGID           uint32 `json:"sgid"`
	FSUID          uint32 `json:"fsuid"`
	FSGID          uint32 `json:"fsgid"`
	SecureBits     uint64 `json:"securebits"`
	CapInheritable uint64 `json:"cap_inheritable"`
	CapPermitted   uint64 `json:"cap_permitted"`
	CapEffective   uint64 `json:"cap_effective"`
	CapBset        uint64 `json:"cap_bset"`
	CapAmbient     uint64 `json:"cap_ambient"`
}

// TetragonEnforcerData mirror of struct tetragon_enforcer_data
type TetragonEnforcerData struct {
	Error   int16  `json:"error"`
	Signal  int16  `json:"signal"`
	FuncID  uint32 `json:"func_id"`
	Arg     uint32 `json:"arg"`
}

// ParseTetragonCreds parses a raw binary tetragon_exec_cred_t struct.
func ParseTetragonCreds(data []byte) (*TetragonExecCred, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("tetragon exec creds data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	return &TetragonExecCred{
		UID:            bo.Uint32(data[0:4]),
		GID:            bo.Uint32(data[4:8]),
		EUID:           bo.Uint32(data[8:12]),
		EGID:           bo.Uint32(data[12:16]),
		SUID:           bo.Uint32(data[16:20]),
		SGID:           bo.Uint32(data[20:24]),
		FSUID:          bo.Uint32(data[24:28]),
		FSGID:          bo.Uint32(data[28:32]),
		SecureBits:     bo.Uint64(data[32:40]),
		CapInheritable: bo.Uint64(data[40:48]),
		CapPermitted:   bo.Uint64(data[48:56]),
		CapEffective:   bo.Uint64(data[56:64]),
		CapBset:        bo.Uint64(data[64:72]),
		CapAmbient:     bo.Uint64(data[72:80]),
	}, nil
}

// EnforceSigkill sends immediate SIGKILL signal to target PID violating security policies.
func EnforceSigkill(pid int) error {
	if pid <= 1 {
		return fmt.Errorf("invalid target PID for sigkill: %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
