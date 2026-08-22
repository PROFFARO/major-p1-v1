package ebpf

import (
	"context"
	"errors"
	"log"
	"sync"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// EventStream reads events from all three BPF ring buffers concurrently
// and pushes parsed Event structs into a unified output channel.
type EventStream struct {
	probes *ProbeSet
	outCh  chan *Event
	wg     sync.WaitGroup
}

// NewEventStream creates a new EventStream that multiplexes events from
// all available ring buffers (sys_tracer, lsm_enforcer, net_filter)
// into a single output channel.
//
// bufSize controls the Go channel buffer depth. A larger buffer absorbs
// bursts from high-throughput probes without dropping events.
func NewEventStream(probes *ProbeSet, bufSize int) *EventStream {
	return &EventStream{
		probes: probes,
		outCh:  make(chan *Event, bufSize),
	}
}

// Events returns the read-only channel where parsed events are delivered.
// Consumers (the WebSocket server, ML pipeline gRPC client, etc.) read
// from this channel.
func (es *EventStream) Events() <-chan *Event {
	return es.outCh
}

// Start launches one goroutine per ring buffer. Each goroutine reads
// raw bytes from the kernel ring buffer, parses them into Event structs,
// and sends them to the unified output channel.
//
// The goroutines run until ctx is cancelled, at which point they drain
// remaining events and exit.
func (es *EventStream) Start(ctx context.Context) {
	// sys_tracer ring buffer: "events"
	if es.probes.SysTracerEvents != nil {
		es.wg.Add(1)
		go es.readRingBuf(ctx, es.probes.SysTracerEvents, "sys_tracer")
	}

	// lsm_enforcer ring buffer: "lsm_events"
	if es.probes.LSMEvents != nil {
		es.wg.Add(1)
		go es.readRingBuf(ctx, es.probes.LSMEvents, "lsm_enforcer")
	}

	// net_filter ring buffer: "net_events"
	if es.probes.NetEvents != nil {
		es.wg.Add(1)
		go es.readRingBuf(ctx, es.probes.NetEvents, "net_filter")
	}

	// Background closer: waits for all readers to exit, then closes the channel
	go func() {
		es.wg.Wait()
		close(es.outCh)
		log.Println("[ringbuf] All ring buffer readers stopped. Channel closed.")
	}()
}

// readRingBuf is the per-ring-buffer goroutine. It uses cilium/ebpf's
// ringbuf.Reader for zero-copy reading from the kernel.
func (es *EventStream) readRingBuf(ctx context.Context, m *cilium.Map, source string) {
	defer es.wg.Done()

	reader, err := ringbuf.NewReader(m)
	if err != nil {
		log.Printf("[ringbuf] ERROR: failed to create reader for %s: %v", source, err)
		return
	}
	defer reader.Close()

	log.Printf("[ringbuf] ✓ Started reading from %s ring buffer", source)

	// When context is cancelled, close the reader to unblock Read()
	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	var eventCount uint64
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("[ringbuf] %s reader closed (total events: %d)", source, eventCount)
				return
			}
			log.Printf("[ringbuf] %s read error: %v", source, err)
			continue
		}

		ev, err := ParseRawEvent(record.RawSample, source)
		if err != nil {
			log.Printf("[ringbuf] %s parse error: %v", source, err)
			continue
		}

		eventCount++

		// Non-blocking send: if the channel is full, drop the event
		// rather than blocking the kernel ring buffer reader.
		select {
		case es.outCh <- ev:
		default:
			// Channel full — event dropped. This prevents backpressure
			// from propagating to the kernel ring buffer.
		}
	}
}
