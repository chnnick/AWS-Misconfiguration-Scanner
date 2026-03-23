from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_start: str = Field(
        description="ISO 8601 timestamp when the scan started (UTC suffix Z).",
    )
    duration_seconds: float = Field(
        ge=0,
        description="Wall-clock duration of the scan in seconds.",
    )
    resource: str = Field(
        description="Logical resource type scanned (e.g. EC2, S3).",
    )
    total_findings: int = Field(
        ge=0,
        description="Count of findings in findings.",
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Flat list of finding objects from the collector.",
    )
