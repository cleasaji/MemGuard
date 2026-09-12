"""
A process's memory-relevant behavior over its lifetime, represented as
an ordered sequence of primitive events. Deliberately low-level (alloc,
permission change, thread creation, specific API names) rather than a
single "malware/benign" label per process -- the fingerprinting layer
that reads this is what has to notice the *pattern*, not read a label
that was handed to it.
"""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class MemoryEvent:
    event_type: str   # "alloc", "exec_mem", "perm_change", "thread_create", "api_call"
    detail: str = ""    # e.g. API name, allocation size class


MemoryTrace = List[MemoryEvent]


# A handful of process-injection-style traces sharing the same underlying
# primitive (allocate memory, make it executable, write shellcode,
# create a remote thread) but differing in specific API choice and
# ordering -- standing in for different "attack families."
FAMILY_A = [
    MemoryEvent("alloc", "VirtualAllocEx"),
    MemoryEvent("perm_change", "PAGE_EXECUTE_READWRITE"),
    MemoryEvent("api_call", "WriteProcessMemory"),
    MemoryEvent("thread_create", "CreateRemoteThread"),
]

FAMILY_B = [
    MemoryEvent("alloc", "NtAllocateVirtualMemory"),
    MemoryEvent("perm_change", "NtProtectVirtualMemory"),
    MemoryEvent("api_call", "NtWriteVirtualMemory"),
    MemoryEvent("thread_create", "NtCreateThreadEx"),
]

FAMILY_C = [
    MemoryEvent("alloc", "VirtualAlloc"),
    MemoryEvent("exec_mem", "PAGE_EXECUTE"),
    MemoryEvent("api_call", "memcpy_shellcode"),
    MemoryEvent("thread_create", "SetThreadContext"),
]

# Family D: NOT used in training -- a genuinely unseen family, but
# sharing the same alloc -> exec -> write -> thread primitive shape.
FAMILY_D_UNSEEN = [
    MemoryEvent("alloc", "MapViewOfFile"),
    MemoryEvent("perm_change", "PAGE_EXECUTE_READ"),
    MemoryEvent("api_call", "QueueUserAPC"),
    MemoryEvent("thread_create", "ResumeThread"),
]

BENIGN_BROWSER = [
    MemoryEvent("alloc", "malloc"),
    MemoryEvent("alloc", "malloc"),
    MemoryEvent("api_call", "ReadFile"),
    MemoryEvent("alloc", "malloc"),
    MemoryEvent("api_call", "ReadFile"),
]

BENIGN_TEXT_EDITOR = [
    MemoryEvent("alloc", "malloc"),
    MemoryEvent("api_call", "ReadFile"),
    MemoryEvent("api_call", "WriteFile"),
    MemoryEvent("alloc", "malloc"),
]
