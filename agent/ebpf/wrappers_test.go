package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestBpfmanManager(t *testing.T) {
	mgr := NewBpfmanManager("/tmp/test_bpfman_pin")
	spec := &ProgramSpec{
		ID:           1,
		Name:         "sys_tracer",
		Type:         "kprobe",
		Priority:     PriorityHigh,
		AttachTarget: "sys_enter",
	}

	if err := mgr.RegisterProgram(spec); err != nil {
		t.Fatalf("Failed to register program spec: %v", err)
	}

	chain := mgr.GetOrderedChain()
	if len(chain) != 1 {
		t.Fatalf("Expected 1 program in ordered chain, got %d", len(chain))
	}

	mgr.SetLoaded("sys_tracer", true)
	p, found := mgr.GetProgram("sys_tracer")
	if !found || !p.Loaded {
		t.Errorf("Expected program sys_tracer to be loaded")
	}
}

func TestECapture_ParseSSLMasterKey(t *testing.T) {
	data := make([]byte, 112)
	bo := binary.LittleEndian
	bo.PutUint32(data[0:4], 5678)
	bo.PutUint32(data[4:8], 1000)
	bo.PutUint64(data[8:16], 123456789)
	copy(data[96:112], "openssl\x00")

	evt, err := ParseSSLMasterKey(data)
	if err != nil {
		t.Fatalf("Unexpected error parsing SSL master key: %v", err)
	}

	if evt.PID != 5678 || evt.Comm != "openssl" {
		t.Errorf("Mismatch in parsed SSL master key event")
	}

	nss := evt.FormatNssKeylog()
	if len(nss) == 0 {
		t.Errorf("Expected NSS keylog string to be generated")
	}
}

func TestEunomiaEngine(t *testing.T) {
	engine := NewEunomiaEngine()
	jsonConfig := []byte(`{
		"meta": {
			"name": "test_pkg",
			"version": "1.0.0",
			"description": "Test dynamic package",
			"bpf_skel_size": 1024,
			"export_types_count": 1
		},
		"fields": [
			{"name": "pid", "type_name": "uint32", "offset": 0, "size": 4}
		]
	}`)

	pkg, err := engine.LoadPackageJSON(jsonConfig)
	if err != nil || pkg == nil {
		t.Fatalf("Failed to load Eunomia package JSON: %v", err)
	}

	rawBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(rawBuf, 9999)

	decoded, err := engine.DecodeDynamicEvent("test_pkg", rawBuf)
	if err != nil {
		t.Fatalf("Failed to decode dynamic event: %v", err)
	}

	if decoded["pid"] != uint32(9999) {
		t.Errorf("Expected decoded pid to be 9999, got %v", decoded["pid"])
	}
}

func TestFalcoEventConversion(t *testing.T) {
	ev := &Event{
		PID:         101,
		PPID:        1,
		Comm:        "nc",
		ExePath:     "/usr/bin/nc",
		Cmdline:     "nc -e /bin/bash",
		ContainerID: "abc123def456",
	}

	falcoEv := ConvertToFalcoEvent(ev, "Terminal Shell in Container", FalcoPriorityNotice, "Shell spawned", []string{"mitre_execution"})
	if falcoEv == nil {
		t.Fatal("Expected non-nil Falco event")
	}

	if !falcoEv.HasTag("mitre_execution") {
		t.Errorf("Expected Falco event to contain tag 'mitre_execution'")
	}
}

func TestGadgetTracer(t *testing.T) {
	data := make([]byte, 512)
	bo := binary.LittleEndian
	bo.PutUint64(data[0:8], 100000)
	bo.PutUint32(data[8:12], uint32(GadgetTypeTraceExec))
	bo.PutUint32(data[12:16], 4321)
	bo.PutUint64(data[32:40], 8888)
	copy(data[48:112], "test-container\x00")

	gEv, err := ParseGadgetEvent(data)
	if err != nil {
		t.Fatalf("Unexpected error parsing Gadget event: %v", err)
	}

	if gEv.PID != 4321 || gEv.Container.ContainerName != "test-container" {
		t.Errorf("Mismatch in parsed Gadget event fields")
	}

	tracer := NewGadgetTracer()
	tracer.RegisterContainer(&gEv.Container)

	meta, found := tracer.LookupContainer(8888)
	if !found || meta.ContainerName != "test-container" {
		t.Errorf("Failed to lookup registered container metadata")
	}
}

func TestKeplerCollector(t *testing.T) {
	data := make([]byte, 136)
	bo := binary.LittleEndian
	bo.PutUint32(data[0:4], 7777)
	bo.PutUint64(data[48:56], 5000)
	copy(data[56:72], "stress\x00")

	proc, err := ParseProcEnergy(data)
	if err != nil {
		t.Fatalf("Failed to parse Kepler proc energy: %v", err)
	}

	kc := NewKeplerCollector()
	kc.RecordProcEnergy(proc)

	snap := kc.GetTotalEnergySnapshot()
	if snap[7777].EnergyMicroJoules != 5000 {
		t.Errorf("Expected 5000 uJ energy reading, got %d", snap[7777].EnergyMicroJoules)
	}
}

func TestKubeArmorPolicyEngine(t *testing.T) {
	engine := NewKubeArmorPolicyEngine()
	engine.SetContainerPosture(10, &KubeArmorContainerPosture{
		MntNS:       10,
		ProcPosture: KubeArmorActionBlock,
		FilePosture: KubeArmorActionAllow,
	})

	act := engine.EvaluateAccess(10, KubeArmorPostureProcess, "/bin/sh")
	if act != KubeArmorActionBlock {
		t.Errorf("Expected process posture to return Block, got %v", act)
	}
}

func TestNetObservCollector(t *testing.T) {
	keyData := make([]byte, 14)
	valData := make([]byte, 36)
	bo := binary.LittleEndian

	bo.PutUint32(keyData[0:4], 0x0100007F) // 127.0.0.1
	bo.PutUint32(keyData[4:8], 0x0100007F) // 127.0.0.1
	bo.PutUint16(keyData[8:10], 8080)
	bo.PutUint16(keyData[10:12], 9090)
	keyData[12] = 6 // TCP
	keyData[13] = 0 // Ingress

	bo.PutUint64(valData[16:24], 1024) // bytes
	bo.PutUint32(valData[24:28], 10)   // packets

	flow, err := ParseNetObservFlow(keyData, valData)
	if err != nil {
		t.Fatalf("Failed to parse NetObserv flow: %v", err)
	}

	coll := NewNetObservCollector()
	coll.RecordFlow(flow)

	if flow.Metrics.Bytes != 1024 {
		t.Errorf("Expected 1024 bytes, got %d", flow.Metrics.Bytes)
	}
}

func TestParcaProfileSample(t *testing.T) {
	data := make([]byte, 200)
	bo := binary.LittleEndian
	bo.PutUint32(data[0:4], 1234)
	bo.PutUint64(data[16:24], 100)
	bo.PutUint32(data[24:28], 1)

	// frame 1
	bo.PutUint64(data[32:40], 0x400000)
	copy(data[60:124], "main.Execute\x00")

	sample, err := ParseParcaProfileSample(data)
	if err != nil {
		t.Fatalf("Failed to parse Parca sample: %v", err)
	}

	if sample.PID != 1234 || len(sample.Frames) != 1 || sample.Frames[0].SymbolName != "main.Execute" {
		t.Errorf("Mismatch in parsed Parca profile sample")
	}
}

func TestPyroscopeAggregator(t *testing.T) {
	agg := NewPyroscopeAggregator()
	key := &PyroscopeStackKey{
		PID:           888,
		UserStackID:   12,
		KernelStackID: 34,
		Comm:          "python",
	}

	agg.RecordStackSample(key, 5)
	flame := agg.GetFlamegraphFormat()

	if len(flame) == 0 {
		t.Errorf("Expected flamegraph snapshot to contain samples")
	}
}

func TestSysmonTranslator(t *testing.T) {
	data := make([]byte, 540)
	bo := binary.LittleEndian
	bo.PutUint32(data[0:4], uint32(SysmonProcessCreate))
	bo.PutUint64(data[4:12], 99999)
	bo.PutUint32(data[12:16], 555)
	copy(data[24:280], "/usr/bin/python3\x00")
	copy(data[280:536], "python3 script.py\x00")

	sysEv, err := TranslateSysmonEvent(data)
	if err != nil {
		t.Fatalf("Failed to translate Sysmon event: %v", err)
	}

	if sysEv.EventID != SysmonProcessCreate || sysEv.ImagePath != "/usr/bin/python3" {
		t.Errorf("Mismatch in parsed Sysmon event fields")
	}
}

func TestTetragonCredsAndSigkill(t *testing.T) {
	data := make([]byte, 80)
	bo := binary.LittleEndian
	bo.PutUint32(data[0:4], 1000)

	cred, err := ParseTetragonCreds(data)
	if err != nil {
		t.Fatalf("Failed to parse Tetragon creds: %v", err)
	}

	if cred.UID != 1000 {
		t.Errorf("Expected UID 1000, got %d", cred.UID)
	}

	err = EnforceSigkill(0)
	if err == nil {
		t.Errorf("Expected error when sending sigkill to PID 0")
	}
}

func TestTraceeEventParser(t *testing.T) {
	data := make([]byte, 96)
	bo := binary.LittleEndian
	bo.PutUint64(data[0:8], 50000)
	bo.PutUint32(data[24:28], 333)
	bo.PutUint32(data[80:84], uint32(TraceeMemProtAlert))

	ctx, err := ParseTraceeEventContext(data)
	if err != nil {
		t.Fatalf("Failed to parse Tracee event context: %v", err)
	}

	if ctx.Task.PID != 333 || ctx.EventID != TraceeMemProtAlert {
		t.Errorf("Mismatch in parsed Tracee event context")
	}
}
