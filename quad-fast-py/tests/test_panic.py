# SPDX-License-Identifier: MIT
"""A Rust panic inside a binding call reaches Python as an exception.

PyO3 catches a panic at every function boundary and raises
`pyo3_runtime.PanicException`, as long as the extension is built with
`panic = "unwind"`. With `panic = "abort"` the interpreter dies instead. The
probe runs in a child interpreter, so an abort is seen as its exit status.

Needs the extension built with the `panic-probe` feature:

    MATURIN_PEP517_ARGS="--features panic-probe" uv run --reinstall-package quad-fast pytest tests/

CI sets QUAD_FAST_REQUIRE_PANIC_PROBE=1, so a build without the probe fails
there instead of skipping.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

native = pytest.importorskip("quad_fast._native")

CHILD = """
import quad_fast._native as native
try:
    native._panic_probe()
except BaseException as error:
    print("caught", type(error).__name__, error)
else:
    raise SystemExit("_panic_probe returned instead of raising")
quad = (("iri", "http://example.com/s"), "http://example.com/p", ("iri", "http://example.com/o", None, None))
print("alive", len(native.read_quad_ipc(native.build_quad_ipc([quad]))))
"""


def test_a_panic_is_a_python_exception_and_the_process_survives():
    if not hasattr(native, "_panic_probe"):
        if os.environ.get("QUAD_FAST_REQUIRE_PANIC_PROBE") == "1":
            pytest.fail("the extension was built without the panic-probe feature")
        pytest.skip("the extension was built without the panic-probe feature")
    result = subprocess.run(
        [sys.executable, "-c", CHILD], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"child exited with {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    assert "caught PanicException panic-probe: deliberate panic" in result.stdout
    assert "alive 1" in result.stdout
