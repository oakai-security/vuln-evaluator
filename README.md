# vuln-evaluator

Autonomous vulnerability evaluation micro-agent developed under the `@oakai-security` organization.

Part of the **Autonomous Vulnerability Remediation, Exception & Governance Pipeline** ([SPEC-020](file:///home/curt/dev/docs/specs/020-vulnerability-exception-and-remediation-governance.md)).

---

## Capabilities & Architecture

Built strictly according to the **Single Responsibility Principle (SRP)**:
1. **Deterministic EPSS Fetch**: Retrieves 30-day exploit probabilities from FIRST.org API.
2. **Process Memory Inspection**: Inspects Linux `/proc/<pid>/maps` to verify whether vulnerable shared objects or binaries are resident in active process RAM.
3. **Focused Local LLM Synthesis**: Invokes local Ollama (`llama3.2:3b`) with a concise, factual prompt to produce structured JSON risk ratings.
4. **Deterministic Fallback Engine**: Employs mathematical risk gates when LLM inference is unreachable.
5. **Unix Domain Socket (UDS) Server**: Exposes `/run/oakai/eval.sock` with kernel-enforced `SO_PEERCRED` caller verification for safe container-to-container IPC.

---

## Installation & Local Development

### Requirements
- Python 3.11+
- `uv` package manager

### Setup
```bash
# Clone and sync virtual environment
uv sync

# Run tests
uv run pytest -v

# Run linter
uv run ruff check .
```

---

## Usage

### 1. One-off CLI Evaluation
```bash
uv run vuln-evaluator evaluate --cve CVE-2024-38077 --package libc6 --cvss 9.8
```

### 2. Batch Evaluation from JSON File
```bash
uv run vuln-evaluator evaluate-file findings.json
```

### 3. Start UDS Server Daemon
```bash
uv run vuln-evaluator serve --socket /run/oakai/eval.sock
```

---

## Container Deployment
```bash
podman build -t oakai/vuln-evaluator:latest .
podman run -d --name vuln-evaluator \
  -v /run/oakai:/run/oakai:rw \
  oakai/vuln-evaluator:latest
```
