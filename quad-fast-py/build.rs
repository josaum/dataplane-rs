// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! Build script emitting extension-module link arguments.

fn main() {
    // On macOS this adds `-undefined dynamic_lookup` to the cdylib link
    // line so Python symbols resolve at import time instead of link time;
    // same mechanism as the released json-fast-py.
    pyo3_build_config::add_extension_module_link_args();
}
