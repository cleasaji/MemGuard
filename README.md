# 🧬 MemGuard

A memory-behavior observatory that fingerprints processes by **how they
use memory** — allocation, permission changes, thread creation, API
sequence shape — and tests whether that fingerprint generalizes to a
**previously unseen attack family**, not just ones it was shown before.

> Research-oriented portfolio project answering: *can behavioral memory
> representations generalize to previously unseen attack families?*

---

## Structural signature, not a name lookup

`fingerprint.py` reduces a trace to event-*type* n-grams (alloc,
perm_change, api_call, thread_create) rather than specific API names,
plus two structural flags: `has_exec_after_alloc` (a region allocated,
then made executable — the write-then-execute shape of shellcode
injection) and `has_remote_thread_primitive`. Two completely different
API vocabularies (`VirtualAllocEx`/`WriteProcessMemory` vs.
`NtAllocateVirtualMemory`/`NtWriteVirtualMemory`) reduce to the *same*
event-type shape when they follow the same operational order — which is
exactly the mechanism that lets an unseen family still get caught.

## The actual experiment

```
Train on:  Family A, Family B, Family C
Test on:   Family D  (never seen as a reference)
```

`generalization_benchmark.py` builds reference fingerprints from only
A/B/C, then classifies Family D — which uses entirely different API
names (`MapViewOfFile`, `QueueUserAPC`, `ResumeThread`) — and two benign
traces it was never tuned against either.

```python
from generalization_benchmark import run_generalization_benchmark

result = run_generalization_benchmark()
print(result.unseen_family_detected)     # True
print(result.benign_false_positives)      # 0
print(result.unseen_result.reason)
```

```
no strong match to a known family (0% similarity), but exhibits the
write-then-execute + remote-thread structural signature of injection
on its own -- flagged as a previously unseen pattern
```

That's the actual research result: Family D shares **zero** n-grams
with any reference family (different API names, so no lexical overlap
at all) and is still correctly flagged — through the structural signature
alone, not memorized similarity.

## Two-tier classification

`similarity.py` combines both signals rather than relying on either
alone:
1. **Similarity to a known family** (Jaccard over trigrams) — catches
   variants of things already seen.
2. **Structural risk** (write-then-execute + remote thread) — catches
   genuinely novel families that share the underlying attack primitive
   even with zero lexical overlap.

A trace only needs to clear the structural check to be flagged as
suspicious-but-unseen; clearing both is reported as a stronger,
named-family match.

## Tests

```bash
pip install -r requirements.txt
cd tests && python -m pytest -v
```

10 tests: structural detection correctly firing on injection-shaped
traces and correctly staying silent on benign ones, Jaccard similarity's
edge cases, known-family classification, benign traces never flagged,
and the core generalization result — Family D detected with zero
benign false positives, confirmed to hold even when the unseen family
shares no exact trigrams with any reference.

## Project layout

```
src/
  memory_trace.py            # MemoryEvent + four family traces (A/B/C for training, D held out)
  fingerprint.py                # event-type n-grams + structural injection signature
  similarity.py                    # Jaccard similarity + two-tier classification
  generalization_benchmark.py         # train on A/B/C, test on D, measure detection + false positives
tests/
  test_memguard.py
```

## Honest scope

Four small hand-authored trace "families" (not a real malware corpus),
and detection rests on the write-then-execute + remote-thread structural
signature generalizing rather than a trained classifier. The
contribution is the *evaluation methodology* — explicitly holding out a
family from training and measuring both detection rate and false
positives on unseen data — which is the same discipline a real
memory-behavior classifier trained on production EDR telemetry would
need to be evaluated under.
