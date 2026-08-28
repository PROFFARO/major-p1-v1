// Package ebpf provides eunomia-bpf dynamic package metadata loading and field parsing.
package ebpf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EunomiaMeta mirror of struct eunomia_bpf_meta_t (eunomia_meta.h)
type EunomiaMeta struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Description      string `json:"description"`
	BPFSkelSize      uint32 `json:"bpf_skel_size"`
	ExportTypesCount uint32 `json:"export_types_count"`
}

// EunomiaFieldMeta mirror of struct eunomia_field_meta_t
type EunomiaFieldMeta struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	Offset   uint32 `json:"offset"`
	Size     uint32 `json:"size"`
}

// EunomiaPackageDescriptor defines a dynamic WASM/JSON eBPF package layout.
type EunomiaPackageDescriptor struct {
	Meta   EunomiaMeta        `json:"meta"`
	Fields []EunomiaFieldMeta `json:"fields"`
}

// EunomiaEngine handles dynamic runtime parsing of WASM/JSON eBPF telemetry headers.
type EunomiaEngine struct {
	packages map[string]*EunomiaPackageDescriptor
}

// NewEunomiaEngine creates a new eunomia engine instance.
func NewEunomiaEngine() *EunomiaEngine {
	return &EunomiaEngine{
		packages: make(map[string]*EunomiaPackageDescriptor),
	}
}

// LoadPackageJSON loads a dynamic eunomia JSON package specification.
func (e *EunomiaEngine) LoadPackageJSON(jsonConfig []byte) (*EunomiaPackageDescriptor, error) {
	var pkg EunomiaPackageDescriptor
	if err := json.Unmarshal(jsonConfig, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse eunomia package JSON: %w", err)
	}

	if pkg.Meta.Name == "" {
		return nil, fmt.Errorf("eunomia package name missing")
	}

	e.packages[pkg.Meta.Name] = &pkg
	return &pkg, nil
}

// DecodeDynamicEvent extracts fields from a raw byte slice based on Eunomia field descriptors.
func (e *EunomiaEngine) DecodeDynamicEvent(pkgName string, rawData []byte) (map[string]interface{}, error) {
	pkg, exists := e.packages[pkgName]
	if !exists {
		return nil, fmt.Errorf("package %q not registered", pkgName)
	}

	decoded := make(map[string]interface{})
	for _, field := range pkg.Fields {
		end := field.Offset + field.Size
		if uint32(len(rawData)) < end {
			continue
		}
		buf := rawData[field.Offset:end]
		switch field.TypeName {
		case "uint32", "u32":
			if len(buf) >= 4 {
				decoded[field.Name] = binaryLittleEndianUint32(buf)
			}
		case "uint64", "u64":
			if len(buf) >= 8 {
				decoded[field.Name] = binaryLittleEndianUint64(buf)
			}
		case "string", "char[]":
			decoded[field.Name] = strings.TrimRight(string(buf), "\x00")
		default:
			decoded[field.Name] = buf
		}
	}

	return decoded, nil
}

func binaryLittleEndianUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func binaryLittleEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
