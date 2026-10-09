from app.detection import (
    DetectionContext,
    DetectionEngine,
    get_engines,
    register_engine,
    run_detection,
    run_detection_report,
)
from app.detection.registry import clear_engines
from app.models import Finding, Severity


class _Engine(DetectionEngine):
    name = "test_engine"

    def __init__(self):
        self.called = 0

    def analyze(self, context: DetectionContext):
        self.called += 1
        return [Finding(engine=self.name, title="suspicious tld", severity=Severity.MEDIUM)]


class _BoomEngine(DetectionEngine):
    name = "boom_engine"

    def analyze(self, context: DetectionContext):
        raise RuntimeError("engine crashed")


def _context() -> DetectionContext:
    return DetectionContext(url="https://example.com", normalized_url="https://example.com", host="example.com")


def test_placeholder_registered_by_default():
    names = [e.name for e in get_engines()]
    assert "placeholder" in names


def test_run_detection_returns_placeholder_empty():
    findings = run_detection(_context())
    assert findings == []


def test_register_and_run_engine():
    original = get_engines()
    clear_engines()
    try:
        engine = _Engine()
        register_engine(engine)
        findings = run_detection(_context())
        assert engine.called == 1
        assert len(findings) == 1
        assert findings[0].engine == "test_engine"
    finally:
        clear_engines()
        for e in original:
            register_engine(e)


def test_broken_engine_is_isolated():
    original = get_engines()
    clear_engines()
    try:
        register_engine(_BoomEngine())
        good = _Engine()
        register_engine(good)
        findings = run_detection(_context())  # must not raise
        assert len(findings) == 1
        assert findings[0].engine == "test_engine"
    finally:
        clear_engines()
        for e in original:
            register_engine(e)


def test_register_rejects_non_engine():
    import pytest

    with pytest.raises(TypeError):
        register_engine(object())


def test_report_flags_failed_engines():
    """A crashed engine must be distinguishable from a clean run."""
    original = get_engines()
    clear_engines()
    try:
        register_engine(_BoomEngine())
        good = _Engine()
        register_engine(good)
        report = run_detection_report(_context())
        assert report.failed_engines == ["boom_engine"]
        assert report.complete is False
        assert [f.engine for f in report.findings] == ["test_engine"]
        # Backwards-compatible helper returns the same findings.
        assert run_detection(_context()) == report.findings
    finally:
        clear_engines()
        for e in original:
            register_engine(e)


def test_report_is_complete_when_all_engines_pass():
    original = get_engines()
    clear_engines()
    try:
        engine = _Engine()
        register_engine(engine)
        report = run_detection_report(_context())
        assert report.failed_engines == []
        assert report.complete is True
        assert len(report.findings) == 1
    finally:
        clear_engines()
        for e in original:
            register_engine(e)
