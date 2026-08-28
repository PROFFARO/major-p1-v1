// Package ebpf provides native eCapture TLS master key and SSL payload event decoding.
package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	SSLMasterKeyLen   = 48
	SSLClientRandomLen = 32

	ECaptureFlagSSLWrite   uint16 = 0x554C
	ECaptureFlagSSLRead    uint16 = 0x5552
	ECaptureFlagMasterKey  uint16 = 0x554B
)

// SSLMasterKeyEvent mirror of struct ssl_master_key_t (ecapture_ssl.h)
type SSLMasterKeyEvent struct {
	PID          uint32        `json:"pid"`
	UID          uint32        `json:"uid"`
	TimestampNs  time.Duration `json:"timestamp_ns"`
	ClientRandom string        `json:"client_random_hex"`
	MasterKey    string        `json:"master_key_hex"`
	Comm         string        `json:"comm"`
}

// ParseSSLMasterKey unmarshals raw BPF bytes from ecapture_ssl probe.
func ParseSSLMasterKey(data []byte) (*SSLMasterKeyEvent, error) {
	if len(data) < 104 {
		return nil, fmt.Errorf("ssl master key data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	pid := bo.Uint32(data[0:4])
	uid := bo.Uint32(data[4:8])
	tsNs := bo.Uint64(data[8:16])

	clientRandHex := hex.EncodeToString(data[16:48])
	masterKeyHex := hex.EncodeToString(data[48:96])
	comm := strings.TrimRight(string(data[96:112]), "\x00")

	return &SSLMasterKeyEvent{
		PID:          pid,
		UID:          uid,
		TimestampNs:  time.Duration(tsNs) * time.Nanosecond,
		ClientRandom: clientRandHex,
		MasterKey:    masterKeyHex,
		Comm:         strings.TrimSpace(comm),
	}, nil
}

// FormatNssKeylog formats the key exchange into standard NSS Key Log Format (for Wireshark TLS decryption).
func (e *SSLMasterKeyEvent) FormatNssKeylog() string {
	return fmt.Sprintf("CLIENT_RANDOM %s %s\n", e.ClientRandom, e.MasterKey)
}
