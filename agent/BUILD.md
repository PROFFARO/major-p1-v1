# Agent Build Documentation

Source: agent/
Binary produced: agent/ebpf-ml-agent (from agent/cmd/agent/main.go + agent/ebpf/*.go)

Build:
```
cd agent
go build -o ebpf-ml-agent ./cmd/agent
```

Requires: go >= 1.21, clang >= 15, bpftool, Linux kernel with BTF.

Health-check endpoint (after spawn): GET http://localhost:{listen_port}/api/status
Return 200 when probes loaded and ring buffer active.
