"""
Prompt templates for the Interactive LLM Security Analyst Copilot.

Provides structured prompts directing Google Gemini / LLMs to behave as a Senior SOC
Security Analyst & eBPF Kernel Forensics Specialist for telemetry-first observability.
"""

# System Instruction defining the LLM Analyst persona
SOC_SYSTEM_INSTRUCTION = """
You are Antigravity SOC Analyst, an elite Principal Security Analyst & Linux Kernel
Forensic Specialist. You analyze eBPF kernel-level telemetry events, multi-model machine
learning predictions (Random Forest, XGBoost, Isolation Forest), and Falco-style behavioral rules.

Your responses must be:
1. Highly technical, precise, and actionable for Security Operations Center (SOC) engineers.
2. Structured in clean GitHub-flavored Markdown.
3. Focused on non-intrusive threat detection, root-cause diagnosis, MITRE ATT&CK alignment, and forensic investigation.
4. Professional, authoritative, and helpful.
"""

# Prompt for synthesizing a single threat detection into a full SOC Incident Report
THREAT_ANALYSIS_PROMPT = """
Analyze the following eBPF Security Observability Event and synthesize a detailed SOC Incident Report.

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
- **Detection Source**: `{action_taken}`

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
1. **Executive Summary**: High-level overview of the detected threat activity.
2. **Technical Threat Breakdown**: Analysis of the 12-dimensional feature vector anomalies.
3. **Probable Attack Vector**: Likely TTPs (MITRE ATT&CK alignment).
4. **Forensic Recommendations**: Recommended manual containment steps for SOC responders.
"""

# Prompt for generating exact forensic containment shell commands
REMEDIATION_PROMPT = """
Provide forensic containment guidance and investigation commands for the following threat:

### Threat Context:
- **PID**: {pid}
- **Process Name**: `{comm}`
- **Binary Path**: `{exe_path}`
- **Destination IP**: `{dst_ip}`
- **Threat Type**: **{threat_name}**
- **Confidence**: `{confidence:.2%}`

---
Generate a step-by-step **Forensic & Investigation Guide** with copy-paste Linux shell commands:
1. **Process Inspection**: Commands to inspect process descriptors, memory map, and `/proc/{pid}`.
2. **Network Investigation**: Commands to analyze network connections and packet captures for destination IP `{dst_ip}`.
3. **Forensic Artifact Preservation**: Commands to preserve dump state for analysis.
"""

# Prompt for interactive conversational Q&A with analysts
ANALYST_CHAT_PROMPT = """
An analyst is asking a question about the eBPF Security Agent state.

### Active System Context:
- **Recent Telemetry & Alert Summary**:
{audit_history_json}

---
### Analyst Query:
"{user_query}"

---
Provide a concise, accurate, and expert answer based on the live system context above.
"""
