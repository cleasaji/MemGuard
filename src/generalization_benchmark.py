"""
The actual research question: can behavioral memory representations
generalize to a previously unseen attack family? Builds reference
fingerprints from families A/B/C only, then classifies family D (never
included as a reference) and a couple of benign traces, and reports
whether the unseen family was still caught.
"""

from dataclasses import dataclass
from typing import Dict, List

from fingerprint import build_fingerprint, BehaviorFingerprint
from similarity import classify, ClassificationResult
from memory_trace import (
    FAMILY_A, FAMILY_B, FAMILY_C, FAMILY_D_UNSEEN, BENIGN_BROWSER, BENIGN_TEXT_EDITOR,
)


@dataclass(frozen=True)
class BenchmarkResult:
    unseen_family_detected: bool
    unseen_result: ClassificationResult
    benign_false_positives: int
    benign_results: List[ClassificationResult]


def build_reference_fingerprints() -> Dict[str, BehaviorFingerprint]:
    """The 'training set' -- known family fingerprints. Family D is
    intentionally excluded here; it only appears at test time."""
    return {
        "family_A": build_fingerprint(FAMILY_A),
        "family_B": build_fingerprint(FAMILY_B),
        "family_C": build_fingerprint(FAMILY_C),
    }


def run_generalization_benchmark() -> BenchmarkResult:
    references = build_reference_fingerprints()

    unseen_fp = build_fingerprint(FAMILY_D_UNSEEN)
    unseen_result = classify(unseen_fp, references)

    benign_traces = [BENIGN_BROWSER, BENIGN_TEXT_EDITOR]
    benign_results = [classify(build_fingerprint(t), references) for t in benign_traces]
    false_positives = sum(1 for r in benign_results if r.is_suspicious)

    return BenchmarkResult(
        unseen_family_detected=unseen_result.is_suspicious,
        unseen_result=unseen_result,
        benign_false_positives=false_positives,
        benign_results=benign_results,
    )
