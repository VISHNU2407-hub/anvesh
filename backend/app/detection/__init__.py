"""Detection package: registry + engine interface.

Public API:
    register_engine(engine)       - add a detection engine
    run_detection(context)        - run all engines and merge findings
    run_detection_report(context) - same, plus which engines failed
    DetectionEngine               - base class teammates subclass
    DetectionContext              - input passed to engines
"""

from .engine import DetectionContext, DetectionEngine
from .registry import (
    DetectionReport,
    get_engines,
    register_engine,
    run_detection,
    run_detection_report,
)

__all__ = [
    "DetectionContext",
    "DetectionEngine",
    "DetectionReport",
    "register_engine",
    "get_engines",
    "run_detection",
    "run_detection_report",
]
