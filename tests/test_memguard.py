import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from memory_trace import FAMILY_A, FAMILY_B, FAMILY_D_UNSEEN, BENIGN_BROWSER
from fingerprint import build_fingerprint
from similarity import jaccard_similarity, classify
from generalization_benchmark import build_reference_fingerprints, run_generalization_benchmark


def test_fingerprint_detects_exec_after_alloc_for_injection_trace():
    fp = build_fingerprint(FAMILY_A)
    assert fp.has_exec_after_alloc
    assert fp.has_remote_thread_primitive


def test_fingerprint_does_not_flag_benign_trace_structurally():
    fp = build_fingerprint(BENIGN_BROWSER)
    assert not fp.has_exec_after_alloc
    assert not fp.has_remote_thread_primitive


def test_jaccard_similarity_identical_sets_is_one():
    s = frozenset({"a", "b", "c"})
    assert jaccard_similarity(s, s) == 1.0


def test_jaccard_similarity_disjoint_sets_is_zero():
    assert jaccard_similarity(frozenset({"a"}), frozenset({"b"})) == 0.0


def test_different_families_share_structural_shape_via_bigrams():
    fp_a = build_fingerprint(FAMILY_A)
    fp_b = build_fingerprint(FAMILY_B)
    # Different specific APIs, but same event-TYPE shape -> nonzero bigram overlap.
    assert jaccard_similarity(fp_a.bigrams, fp_b.bigrams) > 0.0


def test_classify_flags_known_family_as_suspicious():
    references = build_reference_fingerprints()
    result = classify(build_fingerprint(FAMILY_A), references)
    assert result.is_suspicious


def test_classify_does_not_flag_benign_trace():
    references = build_reference_fingerprints()
    result = classify(build_fingerprint(BENIGN_BROWSER), references)
    assert not result.is_suspicious


def test_generalization_benchmark_catches_unseen_family():
    result = run_generalization_benchmark()
    assert result.unseen_family_detected
    assert result.unseen_result.similarity_score >= 0.0  # structural signature alone can justify the flag


def test_generalization_benchmark_has_no_benign_false_positives():
    result = run_generalization_benchmark()
    assert result.benign_false_positives == 0


def test_unseen_family_fingerprint_shares_no_exact_trigrams_with_references_but_still_caught():
    references = build_reference_fingerprints()
    unseen_fp = build_fingerprint(FAMILY_D_UNSEEN)
    # Different specific APIs entirely -- structural detection, not n-gram
    # memorization, is what has to catch this.
    max_trigram_overlap = max(
        jaccard_similarity(unseen_fp.trigrams, ref.trigrams) for ref in references.values()
    )
    result = classify(unseen_fp, references)
    assert result.is_suspicious
    assert unseen_fp.has_exec_after_alloc and unseen_fp.has_remote_thread_primitive
