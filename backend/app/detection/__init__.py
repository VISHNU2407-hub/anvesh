"""Detection package: registry + engine interface.

Public API:
    register_engine(engine)  - add a detection engine
    run_detection(context)   - run all engines and merge findings
    DetectionEngine          - base class teammates subclass
    DetectionContext         - input passed to engines
"""

from .engine import DetectionContext, DetectionEngine
from .registry import get_engines, register_engine, run_detection

__all__ = [
    "DetectionContext",
    "DetectionEngine",
    "register_engine",
    "get_engines",
    "run_detection",
]
