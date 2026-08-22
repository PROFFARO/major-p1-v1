package ebpf

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	cilium "github.com/cilium/ebpf"
)

// TCAttacher manages attaching net_filter.bpf.o programs (tc_ingress and tc_egress)
// to Linux network interfaces (e.g. eth0, wlan0, lo).
type TCAttacher struct {
	ifaces []string
}

// NewTCAttacher creates a TC attacher.
func NewTCAttacher() *TCAttacher {
	return &TCAttacher{}
}

// AttachAllInterfaces discovers active, non-loopback network interfaces (and lo)
// and attaches the compiled tc_ingress and tc_egress programs from net_filter.bpf.o.
func (tc *TCAttacher) AttachAllInterfaces(netColl *cilium.Collection, bpfObjPath string) error {
	if netColl == nil {
		log.Println("[tc] net_filter collection is nil, skipping TC attach")
		return nil
	}

	ingressProg := netColl.Programs["tc_ingress"]
	egressProg := netColl.Programs["tc_egress"]

	if ingressProg == nil || egressProg == nil {
		return fmt.Errorf("tc_ingress or tc_egress program missing in net_filter collection")
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var attachedCount int
	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Attach to both physical/wireless interfaces and loopback
		if err := tc.AttachInterface(iface.Name, bpfObjPath); err != nil {
			log.Printf("[tc] WARN: failed to attach TC filter to interface %s: %v", iface.Name, err)
			continue
		}

		tc.ifaces = append(tc.ifaces, iface.Name)
		attachedCount++
		log.Printf("[tc] ✓ Attached TC ingress/egress filters to interface: %s (index: %d)", iface.Name, iface.Index)
	}

	if attachedCount == 0 {
		log.Println("[tc] WARN: no active interfaces found for TC filter attachment")
	}

	return nil
}

// AttachInterface uses kernel tc tool to create clsact qdisc and attach BPF classifiers.
func (tc *TCAttacher) AttachInterface(ifname string, bpfObjPath string) error {
	// 1. Add clsact qdisc (ignore error if it already exists)
	exec.Command("tc", "qdisc", "add", "dev", ifname, "clsact").Run()

	// 2. Remove any existing BPF filters on ingress/egress
	exec.Command("tc", "filter", "del", "dev", ifname, "ingress").Run()
	exec.Command("tc", "filter", "del", "dev", ifname, "egress").Run()

	// 3. Attach tc_ingress
	cmdIngress := exec.Command("tc", "filter", "add", "dev", ifname, "ingress",
		"bpf", "da", "obj", bpfObjPath, "sec", "tc")
	if out, err := cmdIngress.CombinedOutput(); err != nil {
		return fmt.Errorf("tc ingress attach error on %s: %v (output: %s)", ifname, err, strings.TrimSpace(string(out)))
	}

	// 4. Attach tc_egress
	cmdEgress := exec.Command("tc", "filter", "add", "dev", ifname, "egress",
		"bpf", "da", "obj", bpfObjPath, "sec", "tc")
	if out, err := cmdEgress.CombinedOutput(); err != nil {
		return fmt.Errorf("tc egress attach error on %s: %v (output: %s)", ifname, err, strings.TrimSpace(string(out)))
	}

	return nil
}

// DetachAll removes the TC BPF filters from all attached interfaces on agent shutdown.
func (tc *TCAttacher) DetachAll() {
	for _, ifname := range tc.ifaces {
		log.Printf("[tc] Detaching TC filters from %s ...", ifname)
		exec.Command("tc", "filter", "del", "dev", ifname, "ingress").Run()
		exec.Command("tc", "filter", "del", "dev", ifname, "egress").Run()
		exec.Command("tc", "qdisc", "del", "dev", ifname, "clsact").Run()
	}
	tc.ifaces = nil
	log.Println("[tc] All TC filters detached cleanly.")
}
