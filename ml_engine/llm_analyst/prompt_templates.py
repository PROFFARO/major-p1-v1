"""
Prompt templates for the Interactive LLM Security Analyst Copilot.

Provides structured prompts directing Google Gemini to behave as a Senior SOC
Security Analyst & eBPF Kernel Forensics Specialist.
"""

# System Instruction defining the LLM Analyst persona
SOC_SYSTEM_INSTRUCTION = """
You are Antigravity SOC Analyst, an elite Principal Security Analyst & Linux Kernel
Forensic Specialist. You analyze eBPF kernel-level telemetry events, multi-model machine
learning predictions (Random Forest, XGBoost, Isolation Forest), and automated LSM
enforcement actions.

Your responses must be:
1. Highly technical, precise, and actionable for Security Operations Center (SOC) engineers.
2. Structured in clean GitHub-flavored Markdown.
3. Focused on root-cause analysis, threat indicators, and immediate kernel/system containment.
4. Professional, authoritative, and helpful.
"""

# Prompt for synthesizing a single threat detection into a full SOC Incident Report
THREAT_ANALYSIS_PROMPT = """
Analyze the following eBPF Threat Mitigation Event and synthesize a detailed SOC Incident Report.

### Incident Metadata:
- **Process ID (PID)**: {pid}
- **Process Name (`comm`)**: `{comm}`
- **Executable Path**: `{exe_path}`
- **Parent Process**: `{parent_comm}`
- **Destination IP**: `{dst_ip}`
- **Event Count**: {event_count}

### ML Detection Consensus:
- **Agreed Threat Class**: **{threat_name}**
- **Random Forest Prediction**: `{rf_threat_name}`
- **XGBoost Prediction**: `{xgb_threat_name}`
- **Isolation Forest Score**: `{anomaly_score}` (Anomaly Flag: `{is_anomaly}`)
- **Classifier Confidence**: `{confidence:.2%}`
- **Action Taken**: `{action_taken}`
- **Permanent Block**: `{is_permanent}`
- **Reason**: {reason}

### 12-Dimensional Feature Vector Snapshot:
- Syscall Rate: {syscall_rate:.2f} /sec
- Syscall Shannon Entropy: {syscall_entropy:.4f}
- File Write Ratio: {file_write_ratio:.2%}
- Sensitive File Access Hits: {sensitive_file_access}
- Privilege Escalation Events: {privilege_events}
- Executable Memory (RWX) Hits: {memory_rwx_count}
- Outbound Network Rate: {network_outbound_rate:.2f} /sec
- DNS Query Rate: {dns_query_rate:.2f} /sec
- Parent Suspicious Flag: {parent_is_suspicious}
- Executable Path Depth: {execution_path_depth}
- Failed Syscall Ratio: {failed_syscall_ratio:.2%}
- Unique Syscall Count: {unique_syscall_count}

---
Please provide a comprehensive **SOC Incident Report** in Markdown format containing:
1. **Executive Summary**: High-level overview of the incident.
2. **Technical Threat Breakdown**: Analysis of the 12-dimensional feature vector anomalies.
3. **Probable Attack Vector**: Likely TTPs (MITRE ATT&CK alignment if applicable).
4. **Enforcement Assessment**: Evaluation of the LSM block decision.
5. **Immediate Recommendations**: Top 3 tactical containment steps.
"""

# Prompt for generating exact containment shell commands
REMEDIATION_PROMPT = """
Provide immediate containment commands and forensic remediation steps for the following threat:

### Threat Context:
- **PID**: {pid}
- **Process Name**: `{comm}`
- **Binary Path**: `{exe_path}`
- **Destination IP**: `{dst_ip}`
- **Threat Type**: **{threat_name}**
- **Confidence**: `{confidence:.2%}`

---
Generate a step-by-step **Remediation & Containment Guide** with copy-paste Linux shell commands:
1. **Process Containment**: Commands to freeze, trace, or terminate PID {pid}.
2. **Network Quarantine**: Commands to block destination IP `{dst_ip}` via `iptables` or `ip route`.
3. **Forensic Artifact Preservation**: Commands to inspect file descriptors, environment variables, memory map, and `/proc/{pid}`.
4. **Long-Term Hardening**: System/AppArmor/SELinux/eBPF policy changes to prevent recurrence.
"""

# Prompt for interactive conversational Q&A with analysts
ANALYST_CHAT_PROMPT = """
An analyst is asking a question about the eBPF Security Agent state.

### Active System Context:
- **Active PID/IP Blocks**: {active_blocks_count}
- **Total Evaluated Events**: {total_evaluations}
- **Total Threat Blocks**: {total_blocked}
- **Active Block Details**:
{active_blocks_json}

- **Recent Audit Log Snapshot**:
{audit_history_json}

---
### Analyst Query:
"{user_query}"

---
Provide a concise, accurate, and expert answer based on the live system context above.
"""
