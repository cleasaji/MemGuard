"""
Reduces a raw memory trace to a fingerprint built from *event-type*
n-grams (not specific API names) plus a few structural features. Using
event-type shape rather than exact API names is what lets a fingerprint
generalize: family A's "VirtualAllocEx -> WriteProcessMemory ->
CreateRemoteThread" and family D's completely different API names still
reduce to the same underlying event-type shape
("alloc -> perm_change -> api_call -> thread_create"), which is the
mechanism the generalization benchmark actually tests.
"""

from dataclasses import dataclass
from typing import FrozenSet, List, Set

from memory_trace import MemoryEvent, MemoryTrace


@dataclass(frozen=True)
class BehaviorFingerprint:
    bigrams: FrozenSet[str]
    trigrams: FrozenSet[str]
    has_exec_after_alloc: bool     # a write-then-execute memory region -- classic injection shape
    has_remote_thread_primitive: bool
    alloc_count: int


def _event_type_sequence(trace: MemoryTrace) -> List[str]:
    return [e.event_type for e in trace]


def _ngrams(sequence: List[str], n: int) -> Set[str]:
    return {"-".join(sequence[i:i + n]) for i in range(len(sequence) - n + 1)} if len(sequence) >= n else set()


def build_fingerprint(trace: MemoryTrace) -> BehaviorFingerprint:
    types = _event_type_sequence(trace)

    has_exec_after_alloc = False
    seen_alloc = False
    for t in types:
        if t == "alloc":
            seen_alloc = True
        elif t in ("perm_change", "exec_mem") and seen_alloc:
            has_exec_after_alloc = True

    has_remote_thread = "thread_create" in types and ("alloc" in types)

    return BehaviorFingerprint(
        bigrams=frozenset(_ngrams(types, 2)),
        trigrams=frozenset(_ngrams(types, 3)),
        has_exec_after_alloc=has_exec_after_alloc,
        has_remote_thread_primitive=has_remote_thread,
        alloc_count=types.count("alloc"),
    )
