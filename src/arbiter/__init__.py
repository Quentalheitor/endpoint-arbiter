"""Arbiter package for privileged verdict determination and invariant enforcement.

Contains the privileged Arbiter engine that synthesizes detections from Tier A,
Tier B, and Tier C into immutable Contract C Triage Artifacts.
"""

from src.arbiter.arbiter import Arbiter

__all__ = ["Arbiter"]
