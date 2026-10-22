"""Compute an overall health score for the monitored services."""

from __future__ import annotations


def calculate_health_score(
    total: int,
    running: int,
    critical_stopped: int = 0,
) -> int:
    """Return a health score from 0 to 100.

    Base score is the percentage of running services.
    Stopped critical services incur a heavy penalty.
    """
    if total <= 0:
        return 0
    base = (running / total) * 100
    penalty = min(50, critical_stopped * 20)
    return max(0, min(100, int(base - penalty)))


def score_color(score: int) -> str:
    """Return a semantic color name for a health score."""
    if score >= 90:
        return "success"
    if score >= 70:
        return "warning"
    return "danger"