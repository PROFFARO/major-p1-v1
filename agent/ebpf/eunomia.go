// Package ebpf provides eunomia-bpf dynamic package parsing and WASM module loading metadata.
package ebpf

import (
	"encoding/json"
	"fmt"
)

// EunomiaPackageConfig represents eunomia-bpf's package_config.json metadata format.
type EunomiaPackageConfig struct {
	Name        string                  `json:"name"`
	Version     string                  `json:"version"`
	Description string                  `json:"description"`
	ExportTypes []EunomiaExportType     `json:"export_types"`
	Maps        []EunomiaMapConfig      `json:"maps"`
	Progs       []EunomiaProgConfig     `json:"progs"`
}

// EunomiaExportType describes event field layouts exported by eunomia probes.
type EunomiaExportType struct {
	Name   string         `json:"name"`
	Fields []EunomiaField `json:"fields"`
}

// EunomiaField represents a single field in an exported BPF struct.
type EunomiaField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// EunomiaMapConfig defines eBPF map parameters.
type EunomiaMapConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
}

// EunomiaProgConfig defines eBPF program attachment specs.
type EunomiaProgConfig struct {
	Name      string `json:"name"`
	Attach    string `json:"attach"`
	ProgType  string `json:"prog_type"`
}

// ParseEunomiaPackage parses a raw JSON package specification string into a EunomiaPackageConfig.
func ParseEunomiaPackage(jsonSpec string) (*EunomiaPackageConfig, error) {
	var cfg EunomiaPackageConfig
	err := json.Unmarshal([]byte(jsonSpec), &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse eunomia-bpf package config: %w", err)
	}
	return &cfg, nil
}
