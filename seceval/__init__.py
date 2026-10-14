"""seceval: a tiny evaluation harness for code-security detectors."""

from .dataset import Sample, load_dataset
from .detector import Detector, Finding
from .metrics import Report, SampleResult, evaluate, score_sample

__all__ = [
    "Sample", "load_dataset",
    "Detector", "Finding",
    "Report", "SampleResult", "evaluate", "score_sample",
]
