"""Core evaluation engine combining deterministic facts with focused LLM synthesis."""

import json
import logging
import os

import requests

from .schemas import EpssData, EvaluationResult, MemoryCheckResult, VulnerabilityFinding

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = os.environ.get(
    "OLLAMA_HOST", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
)
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

EVALUATION_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_level": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        },
        "rationale": {
            "type": "string",
        },
    },
    "required": ["threat_level", "rationale"],
}


class VulnerabilityEvaluator:
    """Evaluates contextual vulnerability severity using deterministic facts and local LLM."""

    def __init__(
        self,
        ollama_url: str | None = None,
        model: str | None = None,
        timeout_seconds: int = 60,
    ):
        resolved_url = ollama_url or os.environ.get(
            "OLLAMA_HOST", os.environ.get("OLLAMA_URL", DEFAULT_OLLAMA_URL)
        )
        self.ollama_url = resolved_url.rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL)
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self,
        finding: VulnerabilityFinding,
        epss: EpssData,
        memory: MemoryCheckResult,
    ) -> EvaluationResult:
        """Synthesize verified facts into an enriched evaluation verdict."""
        llm_verdict = self._query_llm_synthesis(finding, epss, memory)

        if llm_verdict:
            threat_level, rationale = llm_verdict
            logger.info(
                "LLM synthesis (%s) evaluated %s (%s) -> %s",
                self.model,
                finding.cve_id,
                finding.package_name,
                threat_level,
            )
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
            memory_visibility=memory.memory_visibility,
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
        mapped_summary = (
            ", ".join(memory.mapped_paths[:3]) if memory.mapped_paths else "None"
        )
        ram_state = (
            f"LOADED IN ACTIVE RAM (Active PIDs: {len(memory.matching_pids)}, Mapped Libraries: {mapped_summary})"
            if memory.in_memory
            else (
                "NOT LOADED IN RAM (0 active processes, full host visibility)"
                if memory.memory_visibility == "full"
                else "NOT FOUND in RAM among processes visible to this scanner "
                "(host visibility is PARTIAL, so root-owned processes were not checked)"
            )
        )
        det_level, _ = self._deterministic_fallback(finding, epss, memory)
        epss_prob_pct = f"{epss.epss_score * 100:.2f}%"
        percentile_ordinal = f"{round(epss.percentile * 100)}th percentile"
        prompt = f"""You are a precise cybersecurity risk evaluator on a hardened Debian 12 Linux host. Write a 1-2 sentence technical rationale explaining the verified threat assessment below:
- CVE ID: {finding.cve_id}
- Package: {finding.package_name} (Installed: {finding.installed_version})
- Description: {finding.description or "OS package vulnerability"}
- Base CVSS: {finding.cvss_base}
- 30-Day Exploit Probability (EPSS): {epss_prob_pct} (Relative Rank: {percentile_ordinal} among all CVEs)
- Host Memory Status: {ram_state}
- Verified Threat Level: {det_level}

Rules:
1. State accurately the Host Memory Status above, including any visibility caveat.
2. State the 30-Day Exploit Probability as {epss_prob_pct}. Never confuse the {percentile_ordinal} rank with a percentage probability.
3. Output MUST be valid JSON with keys "threat_level" (set to "{det_level}") and "rationale" (1-2 concise technical sentences without em-dashes).
"""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "format": EVALUATION_JSON_SCHEMA,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": 160,
                "num_ctx": 2048,
            },
        }

        try:
            url = f"{self.ollama_url}/api/generate"
            response = requests.post(url, json=payload, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
            raw_response = data.get("response", "").strip()

            clean_json = raw_response
            if clean_json.startswith("```"):
                lines = clean_json.splitlines()
                clean_json = "\n".join(
                    lines[1:-1] if lines[-1].startswith("```") else lines[1:]
                )

            parsed = json.loads(clean_json)
            threat_level = str(parsed.get("threat_level", "")).upper().strip()
            rationale = (
                str(parsed.get("rationale", "")).strip().replace("\u2014", " - ")
            )

            valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            if threat_level in valid_levels and rationale:
                # Enforce deterministic risk invariants on threat_level while keeping LLM rationale
                if (
                    not memory.in_memory
                    and epss.epss_score < 0.05
                    and threat_level == "CRITICAL"
                ):
                    threat_level = "LOW"
                elif memory.in_memory and epss.epss_score >= 0.05:
                    threat_level = "CRITICAL"
                return threat_level, rationale

        except (
            requests.RequestException,
            json.JSONDecodeError,
            KeyError,
            ValueError,
        ) as err:
            logger.warning(
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
                f"Active in process RAM (PIDs: {memory.matching_pids[:5]}) with elevated EPSS exploit "
                f"probability ({epss.epss_score:.2%}). Immediate threat."
            )
        elif is_active and high_cvss:
            threat = "HIGH"
            rationale = (
                f"Resident in RAM (PIDs: {memory.matching_pids[:5]}) with CVSS {finding.cvss_base}, "
                f"but low current exploit activity (EPSS: {epss.epss_score:.2%})."
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
