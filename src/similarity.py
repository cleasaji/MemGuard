"""
Classifies a new trace not by exact match against a signature, but by
similarity to previously-seen behavior fingerprints -- which is what
makes it possible to flag "previously unseen malicious behavior pattern
similar to known injection families" instead of only recognizing exact
repeats of known malware.
"""

from dataclasses import dataclass
from typing import Dict, Optional

from fingerprint import BehaviorFingerprint


def jaccard_similarity(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


@dataclass(frozen=True)
class ClassificationResult:
    is_suspicious: bool
    most_similar_family: Optional[str]
    similarity_score: float
    reason: str


def classify(
    fingerprint: BehaviorFingerprint,
    known_families: Dict[str, BehaviorFingerprint],
    similarity_threshold: float = 0.3,
) -> ClassificationResult:
    best_family = None
    best_score = 0.0
    for family_name, known_fp in known_families.items():
        score = jaccard_similarity(fingerprint.trigrams, known_fp.trigrams)
        if score > best_score:
            best_score = score
            best_family = family_name

    structural_risk = fingerprint.has_exec_after_alloc and fingerprint.has_remote_thread_primitive

    if best_score >= similarity_threshold and structural_risk:
        return ClassificationResult(
            is_suspicious=True,
            most_similar_family=best_family,
            similarity_score=round(best_score, 3),
            reason=(
                f"behavior pattern is {best_score:.0%} similar to known family "
                f"'{best_family}' and exhibits a write-then-execute + remote-thread "
                f"structural signature consistent with process injection"
            ),
        )

    if structural_risk and best_score > 0:
        return ClassificationResult(
            is_suspicious=True,
            most_similar_family=best_family,
            similarity_score=round(best_score, 3),
            reason=(
                f"no strong match to a known family ({best_score:.0%} similarity), but "
                f"exhibits the write-then-execute + remote-thread structural signature "
                f"of injection on its own -- flagged as a previously unseen pattern"
            ),
        )

    return ClassificationResult(
        is_suspicious=False,
        most_similar_family=best_family,
        similarity_score=round(best_score, 3),
        reason="no injection-consistent structural signature and no meaningful similarity to known families",
    )
