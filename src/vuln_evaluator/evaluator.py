"""Core evaluation engine combining deterministic facts with focused LLM synthesis."""

import json
import logging

import requests

from .schemas import EpssData, EvaluationResult, MemoryCheckResult, VulnerabilityFinding

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"


class VulnerabilityEvaluator:
    """Evaluates contextual vulnerability severity using deterministic facts and local LLM."""

    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout_seconds: int = 15,
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self,
        finding: VulnerabilityFinding,
        epss: EpssData,
        memory: MemoryCheckResult,
    ) -> EvaluationResult:
        """Synthesize verified facts into an enriched evaluation verdict."""
        # Attempt LLM synthesis if Ollama is available
        llm_verdict = self._query_llm_synthesis(finding, epss, memory)

        if llm_verdict:
            threat_level, rationale = llm_verdict
        else:
            threat_level, rationale = self._deterministic_fallback(
                finding, epss, memory
            )

        return EvaluationResult(
            cve_id=finding.cve_id,
            package_name=finding.package_name,
            installed_version=finding.installed_version,
            cvss_base=finding.cvss_base,
            epss_score=epss.epss_score,
            epss_percentile=epss.percentile,
            in_memory=memory.in_memory,
            matching_pids=memory.matching_pids,
            threat_level=threat_level,
            verdict_rationale=rationale,
        )

    def _query_llm_synthesis(
        self,
        finding: VulnerabilityFinding,
        epss: EpssData,
        memory: MemoryCheckResult,
    ) -> tuple[str, str] | None:
        """Submit verified facts to local Ollama with a hyper-focused prompt."""
        prompt = f"""You are a precise cybersecurity risk evaluator. Evaluate real-world threat severity based ONLY on these verified facts:
- CVE ID: {finding.cve_id}
- Package: {finding.package_name} (Installed: {finding.installed_version})
- Base CVSS: {finding.cvss_base}
- EPSS 30-Day Exploit Probability: {epss.epss_score:.4f} (Percentile: {epss.percentile:.2%})
- Resident in Memory (Active RAM): {memory.in_memory} (Active PIDs: {memory.matching_pids})

Rules:
1. Threat level must be one of: CRITICAL, HIGH, MEDIUM, LOW.
2. If in_memory is False and EPSS < 0.05, threat level must NOT be CRITICAL.
3. If in_memory is True and EPSS >= 0.10, threat level is CRITICAL.
4. Output MUST be valid JSON with keys "threat_level" and "rationale". No markdown formatting or extra text.
"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 150},
        }

        try:
            url = f"{self.ollama_url}/api/generate"
            response = requests.post(url, json=payload, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
            raw_response = data.get("response", "").strip()

            # Clean JSON wrappers if model returned markdown codeblocks
            clean_json = raw_response
            if clean_json.startswith("```"):
                lines = clean_json.splitlines()
                clean_json = "\n".join(
                    lines[1:-1] if lines[-1].startswith("```") else lines[1:]
                )

            parsed = json.loads(clean_json)
            threat_level = parsed.get("threat_level", "").upper()
            rationale = parsed.get("rationale", "")

            valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            if threat_level in valid_levels and rationale:
                return threat_level, rationale

        except (requests.RequestException, json.JSONDecodeError, KeyError) as err:
            logger.info(
                "Ollama synthesis unavailable or returned non-JSON (%s); using deterministic engine",
                err,
            )

        return None

    def _deterministic_fallback(
        self,
        finding: VulnerabilityFinding,
        epss: EpssData,
        memory: MemoryCheckResult,
    ) -> tuple[str, str]:
        """Deterministic risk scoring algorithm based on empirical gates."""
        is_active = memory.in_memory
        high_exploit = epss.epss_score >= 0.05
        high_cvss = finding.cvss_base >= 7.0

        if is_active and high_exploit:
            threat = "CRITICAL"
            rationale = (
                f"Active in process RAM (PIDs: {memory.matching_pids}) with elevated EPSS exploit "
                f"probability ({epss.epss_score:.2%}). Immediate threat."
            )
        elif is_active and high_cvss:
            threat = "HIGH"
            rationale = (
                f"Resident in RAM with CVSS {finding.cvss_base}, but low current exploit activity "
                f"(EPSS: {epss.epss_score:.2%})."
            )
        elif not is_active and high_exploit:
            threat = "MEDIUM"
            rationale = (
                f"Elevated EPSS exploit probability ({epss.epss_score:.2%}), but component is NOT resident "
                f"in active process memory."
            )
        else:
            threat = "LOW"
            rationale = (
                f"Component is not in memory and shows low exploit probability ({epss.epss_score:.2%}). "
                f"Eligible for risk exception."
            )

        return threat, rationale
