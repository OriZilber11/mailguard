from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "suspicious", "malicious", "inconclusive"]
Severity = Literal["low", "medium", "high", "critical", "info", "trust"]


class Attachment(BaseModel):
    filename: str = Field(max_length=255)
    content_type: str = Field(max_length=255)
    size: int
    sha256: str = Field(max_length=64)
    magic_b64: str = Field(max_length=32)  # first 16 bytes, base64


class AnalyzeRequest(BaseModel):
    headers_raw: str = Field(max_length=128_000)
    body_text: str = Field(default="", max_length=256_000)
    body_html: str = Field(default="", max_length=512_000)
    attachments: list[Attachment] = Field(default_factory=list, max_length=30)


class Signal(BaseModel):
    id: str  # e.g. "AUTH_DMARC_FAIL"
    severity: Severity
    title: str
    explanation: str


class AnalyzeResponse(BaseModel):
    engine_version: str
    verdict: Verdict
    summary: str
    signals: list[Signal]
