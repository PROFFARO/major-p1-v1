"""
Universal Interactive LLM Security Analyst Copilot.

Supports ANY LLM Provider, API Key, Base URL, or Local/Cloud Model:
- Google Gemini (gemini-2.5-flash, gemini-pro)
- OpenAI (gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
- Local Ollama / LM Studio / vLLM (llama3, qwen2.5, mistral, deepseek-r1)
- Groq Cloud / DeepSeek / OpenRouter / Together AI
- Custom HTTP OpenAI-compatible API Endpoints

Features:
- Provider-Agnostic Engine: Auto-detects endpoint format or accepts explicit config
- Zero Dependency Lock-In: Uses standard Python `urllib` / `requests` for OpenAI API compatibility
- Dynamic Runtime Configuration: `set_llm_config(api_key, base_url, model_name, provider)`
- Offline Rule-Based Fallback: Gracefully generates rich markdown reports when offline
"""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, List

import numpy as np

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_engine.config import (
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_MODEL_NAME,
    LLM_PROVIDER,
)
from ml_engine.llm_analyst.prompt_templates import (
    SOC_SYSTEM_INSTRUCTION,
    THREAT_ANALYSIS_PROMPT,
    REMEDIATION_PROMPT,
    ANALYST_CHAT_PROMPT,
)

logger = logging.getLogger("ml_engine.llm_analyst.copilot")

# Optional google.generativeai import
import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import google.generativeai as genai
        GENAI_AVAILABLE = True
    except ImportError:
        GENAI_AVAILABLE = False


class LLMSecurityCopilot:
    """
    Universal Interactive LLM Security Analyst Copilot.

    Supports OpenAI-compatible APIs (Ollama, LM Studio, Groq, DeepSeek, OpenAI, vLLM)
    as well as Google Gemini API with dynamic runtime key, base URL, and model switching.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        self.api_key = api_key if api_key is not None else LLM_API_KEY
        self.base_url = (base_url if base_url is not None else LLM_BASE_URL).rstrip("/")
        self.model_name = model_name or LLM_MODEL_NAME or "gemini-2.5-flash"
        self.provider = (provider or LLM_PROVIDER or "auto").lower()

        self._gemini_model = None
        self._configure_engine()

    # ─────────────────────────────────────────────────────────
    # Dynamic Configuration
    # ─────────────────────────────────────────────────────────

    def set_llm_config(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> bool:
        """
        Dynamically update LLM provider configuration at runtime.

        Args:
            api_key: API Key string (e.g. OpenAI / Gemini / Groq key)
            base_url: Custom API Base URL (e.g. "http://localhost:11434/v1" for Ollama)
            model_name: Model identifier (e.g. "llama3:8b", "gpt-4o", "gemini-2.5-flash")
            provider: Provider type ("auto", "openai", "gemini", "ollama", "custom")

        Returns:
            True if configured successfully, False otherwise.
        """
        if api_key is not None:
            self.api_key = api_key.strip()
        if base_url is not None:
            self.base_url = base_url.strip().rstrip("/")
        if model_name is not None:
            self.model_name = model_name.strip()
        if provider is not None:
            self.provider = provider.strip().lower()

        return self._configure_engine()

    def set_api_key(self, api_key: str) -> bool:
        """Alias for setting API key dynamically."""
        return self.set_llm_config(api_key=api_key)

    def _configure_engine(self) -> bool:
        """Configure Gemini SDK or OpenAI-compatible REST connection."""
        # Auto-detect provider if needed
        if self.provider == "auto":
            if self.base_url:
                self._mode = "openai_rest"
            elif self.model_name.startswith("gemini") or "gemini" in self.model_name:
                self._mode = "gemini_sdk"
            elif self.api_key.startswith("sk-"):
                self._mode = "openai_rest"
            else:
                self._mode = "gemini_sdk"
        elif self.provider in ("openai", "ollama", "groq", "deepseek", "openrouter", "custom"):
            self._mode = "openai_rest"
        else:
            self._mode = "gemini_sdk"

        # Initialize Gemini SDK if applicable
        if self._mode == "gemini_sdk":
            if GENAI_AVAILABLE and self.api_key:
                try:
                    genai.configure(api_key=self.api_key)
                    self._gemini_model = genai.GenerativeModel(
                        model_name=self.model_name,
                        system_instruction=SOC_SYSTEM_INSTRUCTION,
                    )
                    logger.info("Configured Gemini SDK model '%s'", self.model_name)
                    return True
                except Exception as e:
                    logger.error("Failed to configure Gemini SDK: %s", e)
                    self._gemini_model = None
            else:
                self._gemini_model = None

        return self.is_available()

    def is_available(self) -> bool:
        """Check if an online LLM generation endpoint is active."""
        if self._mode == "gemini_sdk":
            return GENAI_AVAILABLE and self._gemini_model is not None and bool(self.api_key)
        elif self._mode == "openai_rest":
            # Ollama or local endpoints may not require an API key
            if "127.0.0.1" in self.base_url or "localhost" in self.base_url:
                return True
            return bool(self.api_key) or bool(self.base_url)
        return False

    # ─────────────────────────────────────────────────────────
    # Core LLM Completion Dispatcher
    # ─────────────────────────────────────────────────────────

    def _generate_completion(self, user_prompt: str, system_prompt: str = SOC_SYSTEM_INSTRUCTION) -> Optional[str]:
        """Dispatch prompt to configured LLM endpoint (Gemini SDK or OpenAI REST)."""
        if not self.is_available():
            return None

        if self._mode == "gemini_sdk":
            try:
                response = self._gemini_model.generate_content(user_prompt)
                if response and response.text:
                    return response.text
            except Exception as e:
                logger.error("Gemini SDK request failed: %s", e)
                return None

        elif self._mode == "openai_rest":
            return self._call_openai_rest(user_prompt, system_prompt)

        return None

    def _call_openai_rest(self, user_prompt: str, system_prompt: str) -> Optional[str]:
        """Execute OpenAI-compatible HTTP POST request to base_url/chat/completions."""
        endpoint = self.base_url
        if not endpoint:
            endpoint = "https://api.openai.com/v1"
        if not endpoint.endswith("/chat/completions"):
            endpoint = f"{endpoint}/chat/completions"

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "")
        except Exception as e:
            logger.error("OpenAI REST API call failed (%s): %s", endpoint, e)
            return None

        return None

    # ─────────────────────────────────────────────────────────
    # Threat Analysis (SOC Incident Report)
    # ─────────────────────────────────────────────────────────

    def analyze_threat(
        self,
        action: Dict[str, Any],
        metadata: Dict[str, Any],
        feature_vector: Optional[Any] = None,
    ) -> str:
        prompt = self._build_threat_prompt(action, metadata, feature_vector)
        res = self._generate_completion(prompt)
        if res:
            return res
        return self._fallback_analyze_threat(action, metadata, feature_vector)

    def _build_threat_prompt(
        self,
        action: Dict[str, Any],
        metadata: Dict[str, Any],
        feature_vector: Optional[Any],
    ) -> str:
        features = [0.0] * 12
        if feature_vector is not None:
            if isinstance(feature_vector, np.ndarray):
                features = feature_vector.tolist()
            elif isinstance(feature_vector, (list, tuple)):
                features = list(feature_vector)
        while len(features) < 12:
            features.append(0.0)

        return THREAT_ANALYSIS_PROMPT.format(
            pid=action.get("pid", metadata.get("pid", 0)),
            comm=metadata.get("comm", "unknown"),
            exe_path=metadata.get("exe_path", "unknown"),
            parent_comm=metadata.get("parent_comm", "unknown"),
            dst_ip=metadata.get("dst_ip", "0.0.0.0"),
            event_count=metadata.get("event_count", 0),
            threat_name=action.get("threat_name", "UNKNOWN"),
            rf_threat_name=action.get("rf_threat", action.get("threat_name", "UNKNOWN")),
            xgb_threat_name=action.get("xgb_threat", action.get("threat_name", "UNKNOWN")),
            anomaly_score=action.get("anomaly_score", 0.0),
            is_anomaly=action.get("is_anomaly", False),
            confidence=action.get("confidence", 0.0),
            action_taken=action.get("action_taken", "UNKNOWN"),
            is_permanent=action.get("is_permanent", False),
            reason=action.get("reason", "No reason provided"),
            syscall_rate=features[0],
            syscall_entropy=features[1],
            file_write_ratio=features[2],
            sensitive_file_access=int(features[3]),
            privilege_events=int(features[4]),
            memory_rwx_count=int(features[5]),
            network_outbound_rate=features[6],
            dns_query_rate=features[7],
            parent_is_suspicious=int(features[8]),
            execution_path_depth=int(features[9]),
            failed_syscall_ratio=features[10],
            unique_syscall_count=int(features[11]),
        )

    # ─────────────────────────────────────────────────────────
    # Containment & Remediation Guide
    # ─────────────────────────────────────────────────────────

    def generate_remediation(
        self,
        action: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        prompt = REMEDIATION_PROMPT.format(
            pid=action.get("pid", metadata.get("pid", 0)),
            comm=metadata.get("comm", "unknown"),
            exe_path=metadata.get("exe_path", "/tmp/unknown"),
            dst_ip=metadata.get("dst_ip", "0.0.0.0"),
            threat_name=action.get("threat_name", "UNKNOWN"),
            confidence=action.get("confidence", 0.0),
        )
        res = self._generate_completion(prompt)
        if res:
            return res
        return self._fallback_generate_remediation(action, metadata)

    # ─────────────────────────────────────────────────────────
    # Interactive Q&A Analyst Chat
    # ─────────────────────────────────────────────────────────

    def chat(
        self,
        user_query: str,
        audit_history: Optional[List[Dict[str, Any]]] = None,
        active_blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        audit_json = json.dumps(audit_history[:10] if audit_history else [], indent=2)

        prompt = ANALYST_CHAT_PROMPT.format(
            audit_history_json=audit_json,
            user_query=user_query,
        )
        res = self._generate_completion(prompt)
        if res:
            return res
        return self._fallback_chat(user_query, audit_history, active_blocks)

    # ─────────────────────────────────────────────────────────
    # Offline Rule-Based Fallbacks
    # ─────────────────────────────────────────────────────────

    def _fallback_analyze_threat(
        self,
        action: Dict[str, Any],
        metadata: Dict[str, Any],
        feature_vector: Optional[Any],
    ) -> str:
        pid = action.get("pid", metadata.get("pid", 0))
        comm = metadata.get("comm", "unknown")
        exe = metadata.get("exe_path", "/tmp/malware")
        threat = action.get("threat_name", "UNKNOWN")
        conf = action.get("confidence", 0.0)
        action_taken = action.get("action_taken", "LOG_ONLY")
        dst_ip = metadata.get("dst_ip", "0.0.0.0")

        return f"""# 🛡️ SOC Incident Report (Offline Rule-Based Synthesis)

### Executive Summary
At **{action.get('timestamp', 'NOW')}**, the eBPF Threat Engine detected a high-confidence **{threat}** activity originating from process **`{comm}`** (PID `{pid}`). The ML classifier registered **{conf:.2%} confidence** with LSM kernel enforcement action **`{action_taken}`**.

---

### Process & Telemetry Indicators
- **Process ID**: `{pid}`
- **Process Name**: `{comm}`
- **Executable Path**: `{exe}`
- **Parent Process**: `{metadata.get('parent_comm', 'bash')}`
- **Process Lineage Path**: `{metadata.get('lineage_str', 'unknown')}`
- **Destination IP**: `{dst_ip}`
- **Enforcement Status**: `{action_taken}` (Permanent: `{action.get('is_permanent', False)}`)

---

### Forensic Threat Analysis
1. **Threat Signature**: Class **`{threat}`** matched supervised dual-model consensus (Random Forest + XGBoost).
2. **Kernel LSM Action**: BPF map `pid_blocklist` updated to reject `sys_enter` syscalls with `-EPERM`.
3. **Network Vector**: Destination IP `{dst_ip}` tagged for automated blocklist injection.

---

### Tactical Remediation Checklist
- [x] Process execution blocked at LSM kernel boundary.
- [ ] Freeze process tree: `kill -STOP {pid}`
- [ ] Inspect open sockets: `lsof -p {pid}`
- [ ] Capture memory dump: `gcore {pid}`
- [ ] Terminate process tree: `kill -9 {pid}`
"""

    def _fallback_generate_remediation(
        self,
        action: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> str:
        pid = action.get("pid", metadata.get("pid", 0))
        comm = metadata.get("comm", "unknown")
        dst_ip = metadata.get("dst_ip", "0.0.0.0")
        threat = action.get("threat_name", "UNKNOWN")

        ip_cmd = f"sudo ip route add blackhole {dst_ip}" if dst_ip and dst_ip != "0.0.0.0" else "# No external IP"

        return f"""# 🛠️ Automated Containment & Remediation Guide

### Threat Target
- **Threat Type**: `{threat}`
- **Process**: `{comm}` (PID `{pid}`)
- **Destination IP**: `{dst_ip}`

---

### Step 1: Immediate Process Containment
Execute the following commands in terminal:

```bash
# 1. Pause process execution
sudo kill -STOP {pid}

# 2. Inspect active file descriptors and network connections
sudo lsof -p {pid}

# 3. Inspect working directory and binary
sudo ls -l /proc/{pid}/exe /proc/{pid}/cwd

# 4. Terminate process forcefully
sudo kill -9 {pid}
```

---

### Step 2: Network Quarantine
```bash
# Block destination IP at routing table level
{ip_cmd}

# Alternative: Block via iptables
sudo iptables -A OUTPUT -d {dst_ip} -j DROP
```

---

### Step 3: Forensic Artifact Collection
```bash
# Preserve environment variables
sudo cat /proc/{pid}/environ | tr '\\0' '\\n' > /tmp/proc_{pid}_environ.txt

# Preserve process commandline arguments
sudo cat /proc/{pid}/cmdline | tr '\\0' ' ' > /tmp/proc_{pid}_cmdline.txt
```
"""

    def _fallback_chat(
        self,
        user_query: str,
        audit_history: Optional[List[Dict[str, Any]]],
        active_blocks: Optional[List[Dict[str, Any]]],
    ) -> str:
        total_eval = len(audit_history) if audit_history else 0
        active_count = len(active_blocks) if active_blocks else 0

        return f"""### 🤖 Antigravity Copilot (Offline Mode)

I am currently running in **offline rule-based mode** (no active LLM API key or base URL configured).

**Current System Status**:
- **Active Kernel Blocks**: `{active_count}`
- **Total Evaluated Events**: `{total_eval}`

To connect to any LLM (Ollama, OpenAI, Groq, DeepSeek, Gemini, LM Studio), set your config:
```python
# Example A: Connect to local Ollama / LM Studio
copilot.set_llm_config(base_url="http://localhost:11434/v1", model_name="llama3:8b")

# Example B: Connect to OpenAI / Groq / DeepSeek
copilot.set_llm_config(api_key="sk-...", base_url="https://api.openai.com/v1", model_name="gpt-4o")
```
"""
