"""Data contracts and validation schemas for vulnerability evaluation."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator


class VulnerabilityFinding(BaseModel):
    """Raw finding emitted by vulnerability scanners (e.g., Trivy)."""

    cve_id: str = Field(
        ...,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="Common Vulnerabilities and Exposures identifier",
    )
    package_name: str = Field(
        ..., min_length=1, description="Name of the affected software package"
    )
    installed_version: str = Field(
        ..., min_length=1, description="Currently installed package version"
    )
    fixed_version: str | None = Field(None, description="Patched version if available")
    cvss_base: float = Field(
        ..., ge=0.0, le=10.0, description="Base CVSS severity score"
    )
    description: str | None = Field("", description="Vulnerability summary description")

    @field_validator("cve_id", mode="before")
    def force_uppercase_cve(cls, v: str) -> str:
        """Ensure CVE IDs are converted to uppercase before regex validation."""
        if isinstance(v, str):
            return v.strip().upper()
        return v


class EpssData(BaseModel):
    """Threat intelligence data retrieved from FIRST.org EPSS API."""

    cve_id: str
    epss_score: float = Field(
        ..., ge=0.0, le=1.0, description="30-day exploitation probability"
    )
    percentile: float = Field(
        ..., ge=0.0, le=1.0, description="Percentile ranking relative to all CVEs"
    )
    date: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%d"))


class MemoryCheckResult(BaseModel):
    """Deterministic result of inspecting active process memory maps."""

    in_memory: bool = Field(
        ..., description="Whether affected libraries or binaries are mapped in RAM"
    )
    matching_pids: list[int] = Field(
        default_factory=list, description="List of PIDs with mapped files"
    )
    mapped_paths: list[str] = Field(
        default_factory=list, description="Resolved filesystem paths mapped into memory"
    )
    memory_visibility: str = Field(
        default="partial",
        description=(
            "'full' when a fresh root-owned host memory snapshot (oakai-memscan) covered "
            "all processes; 'partial' when only processes visible to this rootless pod were checked"
        ),
    )


class EvaluationResult(BaseModel):
    """Enriched evaluation verdict synthesized from verified facts."""

    cve_id: str
    package_name: str
    installed_version: str
    cvss_base: float
    epss_score: float
    epss_percentile: float
    in_memory: bool
    memory_visibility: str = "partial"
    matching_pids: list[int]
    threat_level: str = Field(
        ..., description="Calculated threat rating: CRITICAL, HIGH, MEDIUM, LOW"
    )
    verdict_rationale: str = Field(
        ..., description="Concise justification for the calculated threat rating"
    )
    evaluated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
