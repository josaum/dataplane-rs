# SPDX-License-Identifier: MIT
"""Long encoding and decoding calls release the GIL.

A second Python thread records a timestamp every half millisecond while the
main thread makes one long call. If the call holds the GIL, that thread cannot
run until the call returns, so no timestamp falls inside the call. If the call
releases the GIL around its native work, many do.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

quad_fast = pytest.importorskip("quad_fast")

QUADS = 200_000
# Large enough for every workload below; the defaults are sized for services.
BIG = 1 << 40
# A call shorter than this cannot tell the two cases apart reliably.
MIN_CALL_SECONDS = 0.05
# Timestamps the second thread must record inside the call. A call that holds
# the GIL leaves at most one or two, from before it enters native code.
MIN_BEATS_INSIDE = 10


def beats_during(call) -> tuple[float, int]:
    beats: list[float] = []
    done = threading.Event()

    def heartbeat() -> None:
        while not done.is_set():
            beats.append(time.perf_counter())
            time.sleep(0.0005)

    thread = threading.Thread(target=heartbeat)
    thread.start()
    try:
        time.sleep(0.02)
        start = time.perf_counter()
        call()
        end = time.perf_counter()
    finally:
        done.set()
        thread.join()
    return end - start, sum(1 for beat in beats if start < beat < end)


@pytest.fixture(scope="module")
def ipc() -> bytes:
    quads = [
        (
            ("iri", f"http://example.com/s{index}"),
            "http://example.com/p",
            ("literal", f"value {index}", None, None),
        )
        for index in range(QUADS)
    ]
    return quad_fast.build_quad_ipc(
        quads, max_quads=BIG, max_retained_term_bytes=BIG, max_ipc_bytes=BIG
    )


@pytest.fixture(scope="module")
def frames(ipc: bytes) -> list[bytes]:
    return quad_fast.jelly_encode(ipc)


@pytest.fixture(scope="module")
def jsonld() -> str:
    graph = [
        {"@id": f"http://example.com/s{index}", "http://example.com/p": f"value {index}"}
        for index in range(QUADS // 4)
    ]
    return json.dumps({"@graph": graph})


CALLS = {
    "jelly_decode": lambda ipc, frames, jsonld: quad_fast.jelly_decode(
        frames, max_quads=BIG, max_retained_term_bytes=BIG, max_ipc_bytes=BIG
    ),
    "jelly_encode": lambda ipc, frames, jsonld: quad_fast.jelly_encode(ipc),
    "read_quad_ipc": lambda ipc, frames, jsonld: quad_fast.read_quad_ipc(ipc),
    "jsonld_to_quad_ipc": lambda ipc, frames, jsonld: quad_fast.jsonld_to_quad_ipc(
        jsonld,
        max_input_bytes=BIG,
        max_nodes=BIG,
        max_quads=BIG,
        max_retained_term_bytes=BIG,
        max_ipc_bytes=BIG,
    ),
}


@pytest.mark.parametrize("name", sorted(CALLS))
def test_another_thread_runs_during_a_long_call(name, ipc, frames, jsonld):
    call = CALLS[name]
    seconds, inside = beats_during(lambda: call(ipc, frames, jsonld))
    assert seconds >= MIN_CALL_SECONDS, (
        f"{name} took {seconds:.3f}s; the workload is too small to observe the GIL"
    )
    assert inside >= MIN_BEATS_INSIDE, (
        f"{name} ran {seconds:.3f}s but the other thread recorded only {inside} "
        "timestamps inside it: the call holds the GIL"
    )
