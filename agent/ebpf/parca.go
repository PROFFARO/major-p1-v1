// Package ebpf provides Parca continuous DWARF stack unwinding and CPU profile frame decoding.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ParcaFrame mirror of struct parca_frame_t (parca_types.h)
type ParcaFrame struct {
	InstructionPointer uint64 `json:"ip"`
	MappingEnd         uint64 `json:"mapping_end"`
	MappingOffset      uint64 `json:"mapping_offset"`
	LineNumber         uint32 `json:"lineno"`
	SymbolName         string `json:"symbol_name"`
}

// ParcaProfileSample mirror of struct parca_profile_sample_t
type ParcaProfileSample struct {
	PID         uint32        `json:"pid"`
	TGID        uint32        `json:"tgid"`
	TimestampNs time.Duration `json:"timestamp_ns"`
	SampleCount uint64        `json:"sample_count"`
	NumFrames   uint32        `json:"num_frames"`
	Frames      []ParcaFrame  `json:"frames"`
}

// ParseParcaProfileSample parses a raw binary parca_profile_sample_t struct from BPF maps.
func ParseParcaProfileSample(data []byte) (*ParcaProfileSample, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("parca profile sample data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	pid := bo.Uint32(data[0:4])
	tgid := bo.Uint32(data[4:8])
	tsNs := bo.Uint64(data[8:16])
	sampleCount := bo.Uint64(data[16:24])
	numFrames := bo.Uint32(data[24:28])

	sample := &ParcaProfileSample{
		PID:         pid,
		TGID:        tgid,
		TimestampNs: time.Duration(tsNs) * time.Nanosecond,
		SampleCount: sampleCount,
		NumFrames:   numFrames,
		Frames:      make([]ParcaFrame, 0, numFrames),
	}

	// Each frame in C struct is offset after byte 32: 24 bytes (ip, end, offset) + 4 bytes (lineno) + 64 bytes (symbol_name) = 92 bytes
	frameOffset := 32
	for i := uint32(0); i < numFrames && i < 16; i++ {
		if len(data) < frameOffset+92 {
			break
		}
		ip := bo.Uint64(data[frameOffset : frameOffset+8])
		mEnd := bo.Uint64(data[frameOffset+8 : frameOffset+16])
		mOff := bo.Uint64(data[frameOffset+16 : frameOffset+24])
		line := bo.Uint32(data[frameOffset+24 : frameOffset+28])
		symbol := strings.TrimRight(string(data[frameOffset+28:frameOffset+92]), "\x00")

		sample.Frames = append(sample.Frames, ParcaFrame{
			InstructionPointer: ip,
			MappingEnd:         mEnd,
			MappingOffset:      mOff,
			LineNumber:         line,
			SymbolName:         strings.TrimSpace(symbol),
		})
		frameOffset += 92
	}

	return sample, nil
}
