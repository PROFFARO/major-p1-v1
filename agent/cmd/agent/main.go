// Package main provides the CLI entry point for the user-space eBPF telemetry collector agent.
//
// Usage:
//
//	sudo ./ebpf-ml-agent [--bpf-dir ../../bpf/probes] [--listen :8900] [--dataset-dir ./data]
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	procctx "github.com/proffaro/ebpf-ml-agent/context"
	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
	"github.com/proffaro/ebpf-ml-agent/logger"
	"github.com/proffaro/ebpf-ml-agent/mapmgr"
	"github.com/proffaro/ebpf-ml-agent/metrics"
	"github.com/proffaro/ebpf-ml-agent/server"
)

func main() {
	bpfDir := flag.String("bpf-dir", "../../bpf/probes", "Path to directory containing compiled .bpf.o files")
	listenAddr := flag.String("listen", ":8900", "HTTP + WebSocket listen address")
	datasetDir := flag.String("dataset-dir", "./data", "Directory to save .jsonl telemetry dataset files")
	eventBufSize := flag.Int("event-buf", 8192, "Internal event channel buffer depth")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Printf("[agent] Starting eBPF Security Agent (bpf-dir=%s, listen=%s, dataset-dir=%s)", *bpfDir, *listenAddr, *datasetDir)

	// 1. Load and attach eBPF probes
	log.Printf("[agent] Loading eBPF bytecode objects from %s", *bpfDir)
	probes, err := agentebpf.LoadAndAttach(*bpfDir)
	if err != nil {
		log.Fatalf("[agent] Failed to load eBPF probes: %v", err)
	}
	defer probes.Close()

	// 2. Attach Traffic Control (TC) network classifiers
	tcAttacher := agentebpf.NewTCAttacher()
	netObjPath := filepath.Join(*bpfDir, "net_filter.bpf.o")
	if err := tcAttacher.AttachAllInterfaces(probes.NetFilter, netObjPath); err != nil {
		log.Printf("[agent] TC classifier attach warning: %v", err)
	}
	defer tcAttacher.DetachAll()

	// 3. Initialize Process Context Resolver & Telemetry Dataset Exporter
	procResolver := procctx.NewProcessResolver()
	exporter, err := logger.NewExporter(*datasetDir, *eventBufSize)
	if err != nil {
		log.Printf("[agent] Telemetry dataset exporter initialization warning: %v", err)
	}

	// 4. Initialize Metrics Collector & Blocklist Manager
	metricsColl := metrics.NewCollector(probes.PktCounter, probes.DNSCounter)
	bm := mapmgr.NewBlocklistManager(
		probes.PIDBlocklist,
		probes.IPBlocklist,
		probes.NetIPBlocklist,
	)

	// 5. Start Ring Buffer Event Stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if exporter != nil {
		exporter.Start(ctx)
	}

	rawStream := agentebpf.NewEventStream(probes, *eventBufSize)
	rawStream.Start(ctx)

	enrichedCh := make(chan *agentebpf.Event, *eventBufSize)

	// Event processing pipeline
	go func() {
		defer close(enrichedCh)
		for ev := range rawStream.Events() {
			procResolver.Enrich(ev)
			metricsColl.RecordEvent(ev)

			if exporter != nil {
				select {
				case exporter.Input() <- ev:
				default:
				}
			}

			select {
			case enrichedCh <- ev:
			default:
			}
		}
	}()

	// 6. Start REST API & WebSocket Server
	log.Printf("[agent] Listening for WebSocket clients and API requests on %s", *listenAddr)
	srv := server.NewServer(enrichedCh, bm, metricsColl)

	go func() {
		if err := srv.Start(ctx, *listenAddr); err != nil {
			log.Fatalf("[agent] HTTP server error: %v", err)
		}
	}()

	// Graceful Shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[agent] Received signal %v, shutting down", sig)
	cancel()
	log.Println("[agent] Agent shutdown complete")
}
