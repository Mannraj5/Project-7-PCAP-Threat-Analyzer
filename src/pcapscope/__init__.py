"""pcapscope - a dependency-free packet capture parser and threat analyser."""

__version__ = "0.1.0"

from .analyzer import AnalysisResult, analyze  # noqa: E402
from .reader import CaptureError, Frame, read_capture  # noqa: E402

__all__ = ["AnalysisResult", "CaptureError", "Frame", "analyze", "read_capture", "__version__"]
