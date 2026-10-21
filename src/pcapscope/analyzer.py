"""Single-pass pipeline: read -> decode -> statistics + detectors."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from .decode import decode
from .detect import Config, Detector, Finding, default_detectors
from .reader import read_capture
from .stats import TrafficStats


@dataclass(slots=True)
class AnalysisResult:
    capture: str
    sha256: str
    stats: TrafficStats
    findings: list[Finding] = field(default_factory=list)
    elapsed: float = 0.0

    @property
    def threats(self) -> list[Finding]:
        return [f for f in self.findings if f.category == "threat"]

    @property
    def sensor_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.category == "sensor"]


def analyze(path: str | Path, config: Config | None = None,
            detectors: list[Detector] | None = None) -> AnalysisResult:
    """Analyse one capture file in a single pass."""
    config = config or Config()
    detectors = detectors if detectors is not None else default_detectors(config)
    stats = TrafficStats()

    started = time.perf_counter()
    for frame in read_capture(path):
        pkt = decode(frame)
        stats.observe(pkt)
        for detector in detectors:
            detector.observe(pkt)

    findings = [f for detector in detectors for f in detector.findings()]
    findings.sort(key=lambda f: (-f.severity_rank, f.first_seen or 0.0))
    return AnalysisResult(str(path), _sha256(path), stats, findings,
                          time.perf_counter() - started)


def _sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
