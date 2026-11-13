"""Reproduction ledger and the verify-before-claim gate for finding reports.

A finding bulletin may say confirmed only after ``report`` sees a store
record whose status is ``verified`` and whose saved bundle still matches
its hashes. The ledger does not run commands or contact targets.
"""

from .gate import report, render_bulletin
from .store import EvidenceError, EvidenceStore, stable_id

__all__ = [
    "EvidenceError",
    "EvidenceStore",
    "report",
    "render_bulletin",
    "stable_id",
]
